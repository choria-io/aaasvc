package natsstream

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	reconnectCtr = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "choria_aaa_auditor_natsstream_reconnects",
		Help: "Total number of times the NATS Streaming auditor reconnected to the middleware",
	}, []string{"site"})
)

func init() {
	prometheus.MustRegister(reconnectCtr)
}
