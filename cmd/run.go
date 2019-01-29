package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/go-openapi/loads"
	flags "github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/choria-io/aaasvc/api/gen/restapi"
	"github.com/choria-io/aaasvc/api/gen/restapi/operations"
	"github.com/choria-io/aaasvc/authenticators"
	"github.com/choria-io/aaasvc/config"
	"github.com/choria-io/aaasvc/signers"

	"github.com/pkg/errors"
)

func run() error {
	if pidfile != "" {
		err := ioutil.WriteFile(pidfile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
		if err != nil {
			return errors.Wrap(err, "could not write pidfile")
		}

		defer os.Remove(pidfile)
	}

	cfg, err := config.New(cfile)
	if err != nil {
		return err
	}

	if cfg.MonitorPort > 0 {
		servePrometheus(cfg.MonitorPort)
	}

	return serve(cfg)
}

func servePrometheus(port int) {
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func serve(conf *config.Config) error {
	swaggerSpec, err := loads.Analyzed(restapi.SwaggerJSON, "")
	if err != nil {
		log.Fatalln(err)
	}

	api := operations.NewChoriaCentralSigningServiceAPI(swaggerSpec)
	server := restapi.NewServer(api)
	defer server.Shutdown()

	if conf.TLSCertificate == "" || conf.TLSKey == "" || conf.TLSCA == "" {
		return fmt.Errorf("TLS settings are not set")
	}

	server.TLSCertificate = flags.Filename(conf.TLSCertificate)
	server.TLSCertificateKey = flags.Filename(conf.TLSKey)
	server.TLSCACertificate = flags.Filename(conf.TLSCA)

	server.TLSPort = conf.Port
	server.Port = 0
	server.EnabledListeners = []string{"https"}

	if conf.SignerType != "" {
		api.PostSignHandler = operations.PostSignHandlerFunc(signers.SignHandler)
	}

	if conf.AuthenticatorType != "" {
		api.PostLoginHandler = operations.PostLoginHandlerFunc(authenticators.LoginHandler)
	}

	return server.Serve()
}
