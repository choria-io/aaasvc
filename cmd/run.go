package cmd

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/choria-io/aaasvc/api/gen/restapi"
	"github.com/choria-io/aaasvc/api/gen/restapi/operations"
	"github.com/choria-io/aaasvc/authenticators"
	"github.com/choria-io/aaasvc/config"
	"github.com/choria-io/aaasvc/service"
	"github.com/choria-io/aaasvc/signers"
	"github.com/choria-io/go-choria/server"
	"github.com/go-openapi/loads"
	"github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/pkg/errors"
)

func run() error {
	if pidfile != "" {
		err := os.WriteFile(pidfile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
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
	wg := &sync.WaitGroup{}

	if conf.Port > 0 {
		wg.Add(1)
		go serveHTTP(wg, conf)
	}

	if conf.BasicJWTSigner != nil && conf.BasicJWTSigner.ChoriaService {
		wg.Add(1)
		go serveChoria(wg, conf)
	}

	wg.Wait()

	return nil
}

func serveHTTP(wg *sync.WaitGroup, conf *config.Config) error {
	defer wg.Done()

	swaggerSpec, err := loads.Analyzed(restapi.SwaggerJSON, "")
	if err != nil {
		log.Fatalln(err)
	}

	api := operations.NewChoriaCentralSigningServiceAPI(swaggerSpec)
	server := restapi.NewServer(api)
	defer server.Shutdown()

	server.Port = conf.Port
	server.EnabledListeners = []string{"http"}

	if !notls {
		if conf.TLSCertificate == "" || conf.TLSKey == "" {
			return fmt.Errorf("TLS settings are not set")
		}

		server.TLSCertificate = flags.Filename(conf.TLSCertificate)
		server.TLSCertificateKey = flags.Filename(conf.TLSKey)

		// when TLSCA is not set it disables client cert validation / mTLS
		if conf.TLSCA != "" {
			server.TLSCACertificate = flags.Filename(conf.TLSCA)
		}

		server.TLSPort = conf.Port
		server.Port = 0
		server.EnabledListeners = []string{"https"}
	}

	if conf.SignerType != "" {
		api.PostSignHandler = operations.PostSignHandlerFunc(signers.SignHandler)
	}

	if conf.AuthenticatorType != "" {
		api.PostLoginHandler = operations.PostLoginHandlerFunc(authenticators.LoginHandler)
	}

	return server.Serve()
}

func serveChoria(wg *sync.WaitGroup, conf *config.Config) error {
	defer wg.Done()

	fw := conf.Choria()
	fw.Configuration().DisableSecurityProviderVerify = true

	instance, err := server.NewInstance(fw)
	if err != nil {
		return err
	}

	agent, err := service.NewService(fw, Version, fw.Logger("agent"))
	if err != nil {
		return err
	}

	wg.Add(1)
	err = instance.RunServiceHost(ctx, wg)
	if err != nil {
		return err
	}

	err = instance.AgentManager().RegisterAgent(ctx, agent.Name(), agent, instance.Connector())
	if err != nil {
		return err
	}

	return nil
}
