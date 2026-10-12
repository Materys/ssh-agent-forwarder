// ssh-agent-forwarder, a code to authenticate ssh connections using an agent on a different machine
// Copyright (C) 2026 Riccardo Bertossa (MATERYS SRL), Sebastiano Bisacchi (MATERYS SRL)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
package common

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus metrics shared by all the executables (platform, forwarder,
// endpoint). The counters are recorded inside the shared protocol and
// handshake functions, so every binary that imports this package exports
// them; together with the go/process collectors of the default registry they
// are served on the /metrics endpoint started by StartMetricsServer.
var (
	// Handshakes counts protocol handshakes by role and outcome. It is
	// recorded by DoHandshake (client side: forwarder, endpoint) and
	// HandleHandshake (server side: platform).
	Handshakes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "agent_handshakes_total",
		Help: "Total number of protocol handshakes by role and outcome.",
	}, []string{"role", "outcome"})

	messageBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "agent_message_bytes_total",
		Help: "Total number of payload bytes moved through length-prefixed messages, by direction.",
	}, []string{"direction"})

	_ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "agent_active_connections",
		Help: "Number of active connections tracked by the connection tracker.",
	}, func() float64 {
		return float64(GetActiveConnections())
	})
)

// RecordMessageBytes records the payload size of a successfully transferred
// length-prefixed message (direction: "read" or "write").
func RecordMessageBytes(direction string, n int) {
	messageBytes.WithLabelValues(direction).Add(float64(n))
}

// StartMetricsServer starts a background HTTP server exposing the prometheus
// registry at /metrics on the given address. Failures are logged with the
// given prefix; the process keeps running.
func StartMetricsServer(logPrefix, addr string) {
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("%s Metrics server error: %v", logPrefix, err)
		}
	}()
}
