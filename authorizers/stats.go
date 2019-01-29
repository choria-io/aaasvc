package authorizers

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	AllowCtr = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "choria_aaa_authorizer_allowed",
		Help: "Total number of requests that were allowed",
	}, []string{"site", "authorizer", "action"})

	DenyCtr = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "choria_aaa_authorizer_denied",
		Help: "Total number of requests that were denied",
	}, []string{"site", "authorizer", "action"})

	ErrCtr = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "choria_aaa_authorizer_errors",
		Help: "Total number of requests could not be authorized",
	}, []string{"site", "authorizer"})
)

func init() {
	prometheus.MustRegister(AllowCtr)
	prometheus.MustRegister(DenyCtr)
	prometheus.MustRegister(ErrCtr)
}
