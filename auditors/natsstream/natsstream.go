// Package natsstream implements a auditor that publishes audit logs to NATS Streaming
//
// Audit messages are of the type https://choria.io/schemas/choria/signer/v1/signature_audit.json
package natsstream

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/choria-io/aaasvc/auditors"
	"github.com/choria-io/go-protocol/protocol"
	"github.com/choria-io/go-srvcache"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/choria-io/go-choria/backoff"
	"github.com/choria-io/go-choria/choria"
	stan "github.com/nats-io/stan.go"
)

// AuditorConfig configures the NATS Stream auditor
type AuditorConfig struct {
	// ClusterID is the NATS Stream cluster id
	ClusterID string `json:"cluster_id"`

	// ServerList is a comma sep list of NATS Stream servers in format nats://server:port,nats://server:port
	ServerList string `json:"servers"`

	// Topic is the topic to publish messages to
	Topic string `json:"topic"`
}

// NatsStream is a auditors.Auditor that publishes to NATS Stream
type NatsStream struct {
	conf    *AuditorConfig
	servers func() (srvcache.Servers, error)
	sc      stan.Conn
	fw      *choria.Framework
	log     *logrus.Entry
	outbox  chan interface{}
	site    string
}

// Notification is the notification being sent and shall comply with https://choria.io/schemas/choria/signer/v1/signature_audit.json
type Notification struct {
	Protocol string          `json:"protocol"`
	CallerID string          `json:"callerid"`
	Action   string          `json:"action"`
	Site     string          `json:"site"`
	Time     int64           `json:"time"`
	Request  json.RawMessage `json:"request"`
}

// New creates a new instance of the NATS Stream auditor
func New(fw *choria.Framework, c *AuditorConfig, site string) (auditor *NatsStream, err error) {
	auditor = &NatsStream{
		conf:    c,
		fw:      fw,
		servers: c.servers,
		log:     fw.Logger("natsstream"),
		outbox:  make(chan interface{}, 1000),
		site:    site,
	}

	auditor.connect()

	return auditor, nil
}

// Audit implements auditors.Auditor
func (ns *NatsStream) Audit(act auditors.Action, caller string, req protocol.Request) error {
	j, err := req.JSON()
	if err != nil {
		auditors.ErrCtr.WithLabelValues(ns.site, "natsstream").Inc()
		return errors.Wrap(err, "could not JSON encode request")
	}

	n := &Notification{
		Protocol: "io.choria.signer.v1.signature_audit",
		CallerID: caller,
		Action:   auditors.ActionNames[act],
		Site:     ns.site,
		Time:     time.Now().UTC().Unix(),
		Request:  json.RawMessage(j),
	}

	ns.outbox <- n

	return nil
}

func (ns *NatsStream) connect() (err error) {
	ctx := context.Background()

	reconn := make(chan struct{})

	cid, err := choria.NewRequestID()
	if err != nil {
		return errors.Wrap(err, "could not create a client id")
	}

	servers, _ := ns.servers()
	ns.log.Warnf("connecting to stream: %#v\n", servers)

	conn, err := ns.fw.NewConnector(ctx, ns.servers, cid, ns.log)
	if err != nil {
		return fmt.Errorf("could not start NATS connection: %s", err)
	}

	start := func() error {
		ns.log.Infof("%s connecting to NATS Stream", cid)

		ctr := 0

		for {
			ctr++

			if ctx.Err() != nil {
				return errors.New("shutdown called")
			}

			ns.sc, err = stan.Connect(ns.conf.ClusterID, cid, stan.NatsConn(conn.Nats()), stan.SetConnectionLostHandler(func(_ stan.Conn, reason error) {
				ns.log.Errorf("NATS Streaming connection got disconnected, reconnecting: %s", reason)
				reconn <- struct{}{}
			}))
			if err != nil {
				ns.log.Errorf("Could not create initial STAN connection, retrying: %s", err)
				backoff.FiveSec.InterruptableSleep(ctx, ctr)

				continue
			}

			break
		}

		return nil
	}

	watcher := func() {
		ctr := 0

		for {
			select {
			case msg := <-ns.outbox:
				j, err := json.Marshal(msg)
				if err != nil {
					auditors.ErrCtr.WithLabelValues(ns.site, "natsstream").Inc()
					ns.log.Errorf("Could not JSON encode audit message: %s", err)
					continue
				}

				err = ns.sc.Publish(ns.conf.Topic, j)
				if err != nil {
					auditors.ErrCtr.WithLabelValues(ns.site, "natsstream").Inc()
					ns.log.Errorf("Could not publish audit message: %s", err)
					continue
				}

			case <-reconn:
				ctr++

				ns.log.WithField("attempt", ctr).Infof("Attempting to reconnect NATS Stream after reconnection")

				backoff.FiveSec.InterruptableSleep(ctx, ctr)

				err := start()
				if err != nil {
					ns.log.Errorf("Could not restart NATS Streaming connection: %s", err)
					reconn <- struct{}{}
				}

				reconnectCtr.WithLabelValues(ns.site).Inc()

			case <-ctx.Done():
				return
			}
		}
	}

	err = start()
	if err != nil {
		return fmt.Errorf("could not start initial NATS Streaming connection: %s", err)
	}

	go watcher()

	ns.log.Infof("%s connected to NATS Stream", cid)

	return nil
}

func (c *AuditorConfig) servers() (servers srvcache.Servers, err error) {
	servers, err = srvcache.StringHostsToServers(strings.Split(c.ServerList, ","), "nats")
	if err != nil {
		return nil, errors.Wrapf(err, "could not parse stream servers")
	}

	if servers.Count() == 0 {
		return nil, errors.New("no servers specified")
	}

	return servers, nil
}
