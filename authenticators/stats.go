package authenticators

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ErrCtr = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "choria_aaa_authenticator_errors",
		Help: "Total number of authentication requests that failed",
	}, []string{"site", "authenticator"})

	ProcessTime = prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Name: "choria_aaa_authenticator_time",
		Help: "Time taken to handle logins",
	}, []string{"site", "authenticator"})
)

func init() {
	prometheus.MustRegister(ErrCtr)
	prometheus.MustRegister(ProcessTime)
}
