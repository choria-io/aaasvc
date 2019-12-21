package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/choria-io/aaasvc/auditors"
	"github.com/choria-io/aaasvc/authenticators"
	"github.com/choria-io/aaasvc/authenticators/okta"
	"github.com/choria-io/aaasvc/authenticators/userlist"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"

	"github.com/choria-io/aaasvc/auditors/jetstream"
	"github.com/choria-io/aaasvc/auditors/logfile"
	"github.com/choria-io/aaasvc/auditors/natsstream"
	"github.com/choria-io/aaasvc/authorizers/actionlist"
	"github.com/choria-io/aaasvc/authorizers/opa"
	"github.com/choria-io/aaasvc/signers"
	"github.com/pkg/errors"

	"github.com/choria-io/aaasvc/signers/basicjwt"
	"github.com/choria-io/go-choria/choria"
	cconf "github.com/choria-io/go-config"
)

// Config configures the signing service
type Config struct {
	// LogFile is the file to write log entries to
	LogFile string `json:"logfile"`

	// LogLevel is the log level to use, matches Choria log levels
	LogLevel string `json:"loglevel"`

	// ChoriaConfigFile is a configuration file for the choria framework
	ChoriaConfigFile string `json:"choria_config"`

	// AuthenticatorType is the authenticator to use
	//
	// * okta - performs authentication against Okta
	// * userlist - basic user/password/acl list
	AuthenticatorType string `json:"authenticator"`

	// AuditorType is the types of auditor to use, multiple will be called concurrently
	//
	// * logfile - logs audit messages to a file, requires LogfileAuditor config
	// * natsstream - publish audit messages to a NATS Stream
	// * jetstream - publish audit messages to a NATS JetStream topic
	AuditorType []string `json:"auditors"`

	// AuthorizerType is the type of authorizer to use
	//
	// * actionlist - allows actions from the JWT claims, requires no additional config
	// * opa - allows requests based on open policy agent configuration
	AuthorizerType string `json:"authorizer"`

	// SignerType is the type of signer to use
	//
	// * basicjwt - basic JWT based checker, requires BasicJWTSigner config
	SignerType string `json:"signer"`

	// Port to listen on for requests
	Port int `json:"port"`

	// MonitorPort is the port to listen on for requests
	MonitorPort int `json:"monitor_port"`

	// Site is the site to expose in prometheus stats
	Site string `json:"site"`

	// BasicJWTSigner is configuration for the `basicjwt` SignerType
	BasicJWTSigner *basicjwt.SignerConfig `json:"basicjwt_signer"`

	// LogfileAuditor is configuration for the `logfile` AuditorType
	LogfileAuditor *logfile.AuditorConfig `json:"logfile_auditor"`

	// NATSStreamAuditor is configuration for the `natsstream` AuditorType
	NATSStreamAuditor *natsstream.AuditorConfig `json:"natsstream_auditor"`

	// JetStreamAuditor is configuration for the `jetstream` AuditorType
	JetStreamAuditor *jetstream.AuditorConfig `json:"jetstream_auditor"`

	// OktaAuthenticator is configuration for the `okta` AuthorizerType
	OktaAuthenticator *okta.AuthenticatorConfig `json:"okta_authenticator"`

	// UserlistsAuthenticator is a configuration for the `userlist` AuthorizerType
	UserlistsAuthenticator *userlist.AuthenticatorConfig `json:"userlist_authenticator"`

	// TLSCertificate is the certificate to use for listening on login/sign requests
	TLSCertificate string `json:"tls_certificate"`

	// TLSKey is the private key to use for listening on login/sign requests
	TLSKey string `json:"tls_key"`

	// TLSCA is the CA used to create the listening certificate and key
	TLSCA string `json:"tls_ca"`

	fw            *choria.Framework
	audit         []auditors.Auditor
	authenticator authenticators.Authenticator
	signer        signers.Signer
}

// New creates a new config
func New(file string) (conf *Config, err error) {
	conf = &Config{
		LogLevel: "info",
		Site:     "default",
		audit:    []auditors.Auditor{},
	}

	rawconf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, "could not read config file %s", file)
	}

	err = json.Unmarshal(rawconf, conf)
	if err != nil {
		return nil, errors.Wrapf(err, "could not parse config file %s", file)
	}

	ccfg, err := cconf.NewConfig(conf.ChoriaConfigFile)
	if err != nil {
		return nil, errors.Wrapf(err, "could not parse choria config %s", conf.ChoriaConfigFile)
	}

	ccfg.LogFile = conf.LogFile
	ccfg.LogLevel = conf.LogLevel
	ccfg.DisableTLS = true

	conf.fw, err = choria.NewWithConfig(ccfg)
	if err != nil {
		return nil, errors.Wrap(err, "could not configure choria")
	}

	err = configureAuthenticator(conf)
	if err != nil {
		return nil, errors.Wrapf(err, "could not configure %s authenticator", conf.AuthenticatorType)
	}

	err = configureSigner(conf)
	if err != nil {
		return nil, errors.Wrapf(err, "could not configure %s signer", conf.SignerType)
	}

	// all JWT operations should happen in UTC
	jwt.TimeFunc = func() time.Time { return time.Now().UTC() }

	return conf, nil
}

// Choria provides access to the configured choria framework
func (c *Config) Choria() *choria.Framework {
	return c.fw
}

// Logger creates a logger with a specific component set
func (c *Config) Logger(component string) *logrus.Entry {
	return c.fw.Logger(component)
}

// Signer access the configured signers.Signer instance
func (c *Config) Signer() signers.Signer {
	return c.signer
}

func configureAuthenticator(conf *Config) error {
	var err error
	var auth authenticators.Authenticator

	if conf.AuthenticatorType == "" {
		return nil
	}

	switch conf.AuthenticatorType {
	case "okta":
		if conf.OktaAuthenticator == nil {
			return fmt.Errorf("okta authenticator enabled without a valid configuration")
		}

		auth, err = okta.New(conf.OktaAuthenticator, conf.fw.Logger("authenticator"), conf.Site)

	case "userlist":
		if conf.UserlistsAuthenticator == nil {
			return fmt.Errorf("userlist authenticator enabled without a valid configuration")
		}

		auth, err = userlist.New(conf.UserlistsAuthenticator, conf.Logger("authenticator"), conf.Site)

	default:
		err = errors.Errorf("unknown authenticator: %s", conf.AuthenticatorType)
	}

	if err != nil {
		return errors.Wrapf(err, "could not configure %s authenticator", conf.AuthenticatorType)
	}

	conf.authenticator = auth
	authenticators.SetAuthenticator(auth)

	return nil

}

// NewAuditors configures the auditors to use based on config
func newAuditors(conf *Config) (err error) {
	if conf.signer == nil {
		return fmt.Errorf("signer has not been set")
	}

	for _, a := range conf.AuditorType {
		var auditor auditors.Auditor

		switch a {
		case "logfile":
			if conf.LogfileAuditor == nil {
				return fmt.Errorf("logfile auditor enabled without a valid configuration")
			}

			auditor, err = logfile.New(conf.LogfileAuditor, conf.Site)
			if err != nil {
				return fmt.Errorf("logfile auditor failed: %w", err)
			}

		case "natsstream":
			if conf.NATSStreamAuditor == nil {
				return fmt.Errorf("natstream auditor enabled without a valid configuration")
			}

			auditor, err = natsstream.New(conf.Choria(), conf.NATSStreamAuditor, conf.Site)
			if err != nil {
				return fmt.Errorf("natsstream auditor failed: %w", err)
			}
		case "jetstream":
			if conf.JetStreamAuditor == nil {
				return fmt.Errorf("jetstream auditor enabled without a valid configuration")
			}

			auditor, err = jetstream.New(conf.Choria(), conf.JetStreamAuditor, conf.Site)
			if err != nil {
				return fmt.Errorf("jetstream auditor failed: %w", err)
			}
		}

		conf.audit = append(conf.audit, auditor)
	}

	conf.signer.SetAuditors(conf.audit...)

	return nil
}

func newAuthorizer(conf *Config) error {
	if conf.AuthorizerType == "" {
		return nil
	}

	if conf.signer == nil {
		return fmt.Errorf("signer has not been set")
	}

	switch conf.AuthorizerType {
	case "actionlist":
		conf.signer.SetAuthorizer(actionlist.New(conf.Logger("authorizer"), conf.Site))
		return nil

	case "opa":
		conf.signer.SetAuthorizer(opa.New(conf.Logger("authorizer"), conf.Site))
		return nil

	default:
		return fmt.Errorf("unknown authorizer: %s", conf.AuthorizerType)
	}
}

func configureSigner(conf *Config) error {
	if conf.SignerType == "" {
		return nil
	}

	switch conf.SignerType {
	case "basicjwt":
		if conf.BasicJWTSigner == nil {
			return fmt.Errorf("basicjwt signer enabled without a valid configuration")
		}

		signer, err := basicjwt.New(conf.Choria(), conf.BasicJWTSigner, conf.Site)
		if err != nil {
			return errors.Wrap(err, "could not create basicjwt signer")
		}

		conf.signer = signer

	default:
		return fmt.Errorf("unknown signer: %s", conf.SignerType)
	}

	err := newAuditors(conf)
	if err != nil {
		return errors.Wrapf(err, "could not configure auditors")
	}

	err = newAuthorizer(conf)
	if err != nil {
		return errors.Wrapf(err, "could not configure %s authorizer", conf.AuthorizerType)
	}

	signers.SetSigner(conf.signer)

	return nil
}
