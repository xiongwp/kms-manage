// Package metrics exposes Prometheus counters / histograms for kms-manage.
package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// KMSOpTotal 按操作 + 结果维度统计。op: encrypt/decrypt/gen_dek；result: ok/err/no_key/bad_format
var KMSOpTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "kms_op_total",
	Help: "KMS operations by op + result",
}, []string{"op", "result"})

var GRPCRequestTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "kms_grpc_request_total",
	Help: "gRPC requests by method + code",
}, []string{"method", "code"})

var GRPCRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "kms_grpc_request_duration_seconds",
	Help:    "gRPC request latency",
	Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
}, []string{"method"})

var once sync.Once

// Register 注册所有指标；幂等，多次调用没副作用（测试里需要）。
func Register() {
	once.Do(func() {
		prometheus.MustRegister(
			KMSOpTotal,
			GRPCRequestTotal,
			GRPCRequestDuration,
		)
	})
}

func StartServer(addr string, logger *zap.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	go func() {
		logger.Info("metrics http listening", zap.String("addr", addr))
		if err := http.ListenAndServe(addr, mux); err != nil {
			logger.Error("metrics http stopped", zap.Error(err))
		}
	}()
}
