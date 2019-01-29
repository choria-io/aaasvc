package auditors

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ErrCtr = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "choria_aaa_auditor_errors",
		Help: "Total number of audit requests that failed",
	}, []string{"site", "auditor"})
)

func init() {
	prometheus.MustRegister(ErrCtr)
}
