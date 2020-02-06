// Package jetstream implements a auditor that publishes audit logs to NATS JetStream
//
// Audit messages are of the type https://choria.io/schemas/choria/signer/v1/signature_audit.json
package jetstream

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/choria-io/aaasvc/auditors"
	"github.com/choria-io/aaasvc/auditors/notification"
	"github.com/choria-io/go-choria/choria"
	"github.com/choria-io/go-choria/protocol"
	"github.com/choria-io/go-choria/srvcache"
	"github.com/sirupsen/logrus"
)

// AuditorConfig configures the JetStream auditor
type AuditorConfig struct {
	// ServerList is a comma sep list of JetStream servers in format nats://server:port,nats://server:port
	ServerList string `json:"servers"`

	// Topic is the topic to publish messages to
	Topic string `json:"topic"`
}

// JetStream is a auditors.Auditor that publishes to NATS JetStream
type JetStream struct {
	conf    *AuditorConfig
	servers func() (srvcache.Servers, error)
	nc      choria.Connector
	fw      *choria.Framework
	log     *logrus.Entry
	outbox  chan interface{}
	site    string
}

// New creates a new instance of the JetStream auditor
func New(fw *choria.Framework, c *AuditorConfig, site string) (auditor *JetStream, err error) {
	ctx := context.Background()

	auditor = &JetStream{
		conf:    c,
		fw:      fw,
		servers: c.servers,
		log:     fw.Logger("jetstream"),
		outbox:  make(chan interface{}, 1000),
		site:    site,
	}

	err = auditor.connect(ctx)
	if err != nil {
		return nil, err
	}

	go auditor.worker(ctx)

	return auditor, nil
}

// Audit implements auditors.Auditor
func (a *JetStream) Audit(act auditors.Action, caller string, req protocol.Request) error {
	j, err := req.JSON()
	if err != nil {
		auditors.ErrCtr.WithLabelValues(a.site, "jetstream").Inc()
		return fmt.Errorf("could not JSON encode request: %w", err)
	}

	n := &notification.SignerAudit{
		Protocol: "io.choria.signer.v1.signature_audit",
		CallerID: caller,
		Action:   auditors.ActionNames[act],
		Site:     a.site,
		Time:     time.Now().UTC().Unix(),
		Request:  json.RawMessage(j),
	}

	a.outbox <- n

	return nil
}

func (a *JetStream) worker(ctx context.Context) {
	for {
		select {
		case msg := <-a.outbox:
			j, err := json.Marshal(msg)
			if err != nil {
				auditors.ErrCtr.WithLabelValues(a.site, "jetstream").Inc()
				a.log.Errorf("Could not JSON encode audit message: %s", err)
				continue
			}

			err = a.nc.PublishRaw(a.conf.Topic, j)
			if err != nil {
				auditors.ErrCtr.WithLabelValues(a.site, "jetstream").Inc()
				a.log.Errorf("Could not publish audit message: %s", err)
				continue
			}

		case <-ctx.Done():
			return
		}
	}
}

func (a *JetStream) connect(ctx context.Context) (err error) {
	a.nc, err = a.fw.NewConnector(ctx, a.servers, choria.UniqueID(), a.log)
	if err != nil {
		return fmt.Errorf("could not start NATS connection: %w", err)
	}

	return nil
}

func (c *AuditorConfig) servers() (servers srvcache.Servers, err error) {
	servers, err = srvcache.StringHostsToServers(strings.Split(c.ServerList, ","), "nats")
	if err != nil {
		return nil, fmt.Errorf("could not parse stream servers: %w", err)
	}

	if servers.Count() == 0 {
		return nil, fmt.Errorf("no servers specified")
	}

	return servers, nil
}
