package main

import (
        "flag"
        "log"
        "net/http"
        "samba-exporter/internal/collector"
        "samba-exporter/internal/config"

        "github.com/prometheus/client_golang/prometheus"
        "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
        scrapeDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
                Name: "samba_exporter_scrape_duration_seconds",
                Help: "Время сбора метрик",
        })
)

func main() {
        configPath := flag.String("config.file", "/etc/samba_exporter/config.yaml", "Path to config")
        flag.Parse()

        cfg, err := config.Load(*configPath)
        if err != nil {
                log.Printf("Warning: could not load config, using defaults: %v", err)
                // Установка дефолтов если нужно
        }

        sc := collector.NewSambaCollector(cfg, scrapeDuration)
        prometheus.MustRegister(sc)
        prometheus.MustRegister(scrapeDuration)

        log.Printf("Samba Exporter запущен на %s", cfg.Server.ListenAddress)
        http.Handle("/metrics", promhttp.Handler())
        log.Fatal(http.ListenAndServe(cfg.Server.ListenAddress, nil))
}
