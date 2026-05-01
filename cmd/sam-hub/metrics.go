package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	samHubActiveNodes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sam_hub_active_nodes",
		Help: "The current number of nodes connected/enrolled in the mesh.",
	})

	samHubEnrollmentTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sam_hub_enrollment_total",
		Help: "Total enrollment requests, partitioned by status.",
	}, []string{"status"})

	samHubMeshEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sam_hub_mesh_events_total",
		Help: "Total gossip events processed, partitioned by event_type.",
	}, []string{"event_type"})

	samHubKeyRotationsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sam_hub_key_rotations_total",
		Help: "The number of times the Hub has rotated its cryptographic keys.",
	})
)
