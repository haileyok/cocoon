package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	NAMESPACE = "cocoon"
)

var (
	RelaysConnected = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: NAMESPACE,
		Name:      "relays_connected",
		Help:      "number of connected relays, by host",
	}, []string{"host"})

	RelaySends = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: NAMESPACE,
		Name:      "relay_sends",
		Help:      "number of events sent to a relay, by host",
	}, []string{"host"})
)
