package signers

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ErrorCtr = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "choria_aaa_signer_errors",
		Help: "Total number of requests that could not be signed",
	}, []string{"site", "signer"})

	AllowedCtr = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "choria_aaa_signer_allowed",
		Help: "Total number of requests that were allowed by the authorizer",
	}, []string{"site", "signer"})

	DenyCtr = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "choria_aaa_signer_denied",
		Help: "Total number of requests that were denied by the authorizer",
	}, []string{"site", "signer"})

	InvalidTokenCtr = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "choria_aaa_signer_invalid_token",
		Help: "Total number of requests that contained invalid tokens",
	}, []string{"site", "signer"})
)

func init() {
	prometheus.MustRegister(ErrorCtr)
	prometheus.MustRegister(AllowedCtr)
	prometheus.MustRegister(DenyCtr)
	prometheus.MustRegister(InvalidTokenCtr)
}
