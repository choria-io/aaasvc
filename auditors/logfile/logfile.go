// Package logfile is a auditor that simply logs to a file
package logfile

import (
	"os"

	"github.com/choria-io/aaasvc/auditors"
	"github.com/choria-io/go-choria/protocol"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// AuditorConfig configures the logfile auditor
type AuditorConfig struct {
	Logfile string `json:"logfile"`
}

// Logfile is a auditors.Auditor that logs to a file
type Logfile struct {
	log  *logrus.Entry
	site string
}

// New creates a new auditor
func New(c *AuditorConfig, site string) (auditor *Logfile, err error) {
	log := logrus.New()
	log.Out = os.Stdout

	if c.Logfile != "" {
		log.Formatter = &logrus.JSONFormatter{}
		file, err := os.OpenFile(c.Logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, errors.Wrapf(err, "could not set up logfile %s", c.Logfile)
		}

		log.Out = file
	}

	return &Logfile{
		log:  logrus.NewEntry(log).WithFields(logrus.Fields{"auditor": "logfile", "site": site}),
		site: site,
	}, nil
}

// Audit implements auditors.Auditor
func (l *Logfile) Audit(act auditors.Action, caller string, req protocol.Request) error {
	j, err := req.JSON()
	if err != nil {
		auditors.ErrCtr.WithLabelValues(l.site, "logfile").Inc()
		return errors.Wrap(err, "could not create JSON request")
	}

	l.log.WithFields(logrus.Fields{"caller": caller, "action": auditors.ActionNames[act]}).Infof(j)

	return nil
}
