package server

import (
        "context"
        "log"
        "net/http"
        "os"
        "os/signal"
        "samba-exporter/internal/config"
        "syscall"
        "time"
        "github.com/prometheus/client_golang/prometheus"
        "github.com/prometheus/client_golang/prometheus/promhttp"
)

func Run(cfg *config.Config, collector prometheus.Collector) error {
        prometheus.MustRegister(collector)

        mux := http.NewServeMux()
        mux.Handle("/metrics", promhttp.Handler())

        srv := &http.Server{
                Addr:         cfg.Server.ListenAddress,
                Handler:      mux,
                ReadTimeout:  cfg.Server.ReadTimeout,
                WriteTimeout: cfg.Server.WriteTimeout,
        }

        done := make(chan os.Signal, 1)
        signal.Notify(done, os.Interrupt, syscall.SIGTERM)

        go func() {
                log.Printf("Server started on %s", cfg.Server.ListenAddress)
                if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
                        log.Fatalf("Listen error: %v", err)
                }
        }()

        <-done
        log.Println("Shutting down...")
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        return srv.Shutdown(ctx)
}
