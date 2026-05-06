package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

// Структура конфигурации
type Config struct {
	Server struct {
		ListenAddress string `yaml:"listen_address"`
	} `yaml:"server"`
	Samba struct {
		ConfigPath   string `yaml:"config_path"`
		SizeInterval string `yaml:"size_interval"`
	} `yaml:"samba"`
}

// Данные для кэша дисков
type ShareStats struct {
	UsedBytes      float64
	TotalCapacity  float64
	AvailableBytes float64
}

var (
	shareCache   = make(map[string]ShareStats)
	cacheMutex   sync.RWMutex
	globalConfig Config

	// Метрика длительности сбора данных
	scrapeDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "samba_exporter_scrape_duration_seconds",
		Help: "Time taken to collect metrics",
	})
)

// Извлечение шар из smb.conf
func getShares(path string) map[string]string {
	file, err := os.Open(path)
	if err != nil {
		log.Printf("ERROR: smb.conf not found: %v", err)
		return nil
	}
	defer file.Close()

	shares := make(map[string]string)
	scanner := bufio.NewScanner(file)
	currentSection := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.ToLower(line[1 : len(line)-1])
			if name != "global" && name != "homes" && name != "printers" {
				currentSection = name
			} else {
				currentSection = ""
			}
			continue
		}
		if currentSection != "" && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if strings.ToLower(strings.TrimSpace(parts[0])) == "path" {
				shares[currentSection] = strings.TrimSpace(parts[1])
			}
		}
	}
	return shares
}

// Параллельное обновление метрик дисков (du + statfs)
func updateShareStats() {
	interval, _ := time.ParseDuration(globalConfig.Samba.SizeInterval)
	if interval == 0 {
		interval = 10 * time.Minute
	}

	for {
		detected := getShares(globalConfig.Samba.ConfigPath)
		var wg sync.WaitGroup

		for name, path := range detected {
			wg.Add(1)
			go func(sName, sPath string) {
				defer wg.Done()
				
				stats := ShareStats{}
				// du для размера папки
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
				out, err := exec.CommandContext(ctx, "du", "-sb", sPath).Output()
				cancel()

				if err == nil {
					fields := strings.Fields(string(out))
					if len(fields) > 0 {
						stats.UsedBytes, _ = strconv.ParseFloat(fields[0], 64)
					}
				}

				// syscall для свободного места на разделе
				var fs syscall.Statfs_t
				if err := syscall.Statfs(sPath, &fs); err == nil {
					stats.TotalCapacity = float64(fs.Blocks) * float64(fs.Bsize)
					stats.AvailableBytes = float64(fs.Bavail) * float64(fs.Bsize)
				}

				cacheMutex.Lock()
				shareCache[sName] = stats
				cacheMutex.Unlock()
			}(name, path)
		}
		wg.Wait()
		time.Sleep(interval)
	}
}

// Коллектор Samba
type SambaCollector struct{}

func (sc SambaCollector) Describe(ch chan<- *prometheus.Desc) {}

func (sc SambaCollector) Collect(ch chan<- prometheus.Metric) {
	timer := prometheus.NewTimer(scrapeDuration)
	defer timer.ObserveDuration()

	out, err := exec.Command("smbstatus", "--json").Output()
	upVal := 1.0
	if err != nil {
		upVal = 0.0
	}
	
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("samba_up", "Samba status", nil, nil),
		prometheus.GaugeValue, upVal,
	)

	if err == nil {
		var data struct {
			Sessions map[string]struct {
				Username        string `json:"username"`
				ProtocolVersion string `json:"protocol_version"`
				RemoteMachine   string `json:"remote_machine"`
			} `json:"sessions"`
			Locks map[string]struct {
				Path string `json:"path"`
			} `json:"locks"`
		}
		
		if err := json.Unmarshal(out, &data); err != nil {
			log.Printf("JSON Error: %v", err)
		} else {
			// Сессии с IP и протоколом
			sessDesc := prometheus.NewDesc("samba_session_info", "Session details", []string{"user", "protocol", "client_address"}, nil)
			for _, s := range data.Sessions {
				if s.Username != "" && !strings.HasSuffix(s.Username, "$") {
					ch <- prometheus.MustNewConstMetric(sessDesc, prometheus.GaugeValue, 1, s.Username, s.ProtocolVersion, s.RemoteMachine)
				}
			}

			// Инфо о блокировках
			lockPathDesc := prometheus.NewDesc("samba_file_lock_info", "Locked paths", []string{"path"}, nil)
			for _, l := range data.Locks {
				ch <- prometheus.MustNewConstMetric(lockPathDesc, prometheus.GaugeValue, 1, l.Path)
			}
			
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc("samba_locked_files_total", "Count of locks", nil, nil),
				prometheus.GaugeValue, float64(len(data.Locks)),
			)
		}
	}

	// Метрики из кэша
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	for name, stats := range shareCache {
		lbl := []string{name}
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("samba_share_used_bytes", "Used", []string{"share"}, nil), prometheus.GaugeValue, stats.UsedBytes, lbl...)
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("samba_share_capacity_bytes", "Capacity", []string{"share"}, nil), prometheus.GaugeValue, stats.TotalCapacity, lbl...)
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("samba_share_available_bytes", "Free", []string{"share"}, nil), prometheus.GaugeValue, stats.AvailableBytes, lbl...)
	}
}

func main() {
	configPath := flag.String("config.file", "/etc/samba_exporter/config.yaml", "Path to config")
	flag.Parse()

	cfgData, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Config Error: %v", err)
	}
	yaml.Unmarshal(cfgData, &globalConfig)

	// Регистрируем только кастомный коллектор и длительность
	// Go/Process метрики регистрируются библиотекой автоматически
	prometheus.MustRegister(SambaCollector{})
	prometheus.MustRegister(scrapeDuration)

	go updateShareStats()

	log.Printf("Starting Exporter on %s", globalConfig.Server.ListenAddress)
	http.Handle("/metrics", promhttp.Handler())
	
	if err := http.ListenAndServe(globalConfig.Server.ListenAddress, nil); err != nil {
		log.Fatal(err)
	}
}
