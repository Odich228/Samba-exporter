package collector

import (
        "bufio"
        "encoding/json"
        "os"
        "os/exec"
        "strconv"
        "strings"
        "sync"
        "syscall"
        "time"

        "samba-exporter/internal/config"
        "github.com/prometheus/client_golang/prometheus"
)

// ADData хранит списки пользователей и групп
type ADData struct {
        Users  []string
        Groups []string
}

// ShareStats хранит данные о дисковом пространстве шары
type ShareStats struct {
        UsedBytes      float64
        TotalCapacity  float64
        AvailableBytes float64
}

// SambaCollector основной тип коллектора
type SambaCollector struct {
        cfg            *config.Config
        shareCache     map[string]ShareStats
        adCache        ADData
        mu             sync.RWMutex
        scrapeDuration prometheus.Histogram
}

// NewSambaCollector создает экземпляр и запускает фоновые задачи
func NewSambaCollector(cfg *config.Config, sd prometheus.Histogram) *SambaCollector {
        sc := &SambaCollector{
                cfg:            cfg,
                shareCache:     make(map[string]ShareStats),
                scrapeDuration: sd,
        }
        // Запускаем циклы обновления
        go sc.updateShareStats()
        go sc.updateADCache()
        return sc
}

// getShares парсит smb.conf для поиска путей к шарам
func (sc *SambaCollector) getShares(path string) map[string]string {
        file, err := os.Open(path)
        if err != nil {
                return nil
        }
        defer file.Close()
        shares := make(map[string]string)
        scanner := bufio.NewScanner(file)
        currentSection := ""
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
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

// updateShareStats фоновое обновление размеров шар (du и statfs)
func (sc *SambaCollector) updateShareStats() {
        for {
                interval, err := time.ParseDuration(sc.cfg.Samba.Intervals.SizeScan)
                if err != nil {
                        interval = 1 * time.Minute
                }

                if sc.cfg.Samba.Collectors.EnableDu {
                        detected := sc.getShares(sc.cfg.Samba.ConfigPath)
                        for name, path := range detected {
                                stats := ShareStats{}
                                out, err := exec.Command("du", "-sb", path).Output()
                                if err == nil {
                                        f := strings.Fields(string(out))
                                        if len(f) > 0 {
                                                stats.UsedBytes, _ = strconv.ParseFloat(f[0], 64)
                                        }
                                }
                                var fs syscall.Statfs_t
                                if err := syscall.Statfs(path, &fs); err == nil {
                                        stats.TotalCapacity = float64(fs.Blocks) * float64(fs.Bsize)
                                        stats.AvailableBytes = float64(fs.Bavail) * float64(fs.Bsize)
                                }
                                sc.mu.Lock()
                                sc.shareCache[name] = stats
                                sc.mu.Unlock()
                        }
                }
                time.Sleep(interval)
        }
}

// updateADCache фоновое обновление данных из wbinfo
func (sc *SambaCollector) updateADCache() {
        for {
                interval, err := time.ParseDuration(sc.cfg.Samba.Intervals.AdUpdate)
                if err != nil {
                        interval = 30 * time.Minute
                }

                if sc.cfg.Samba.Collectors.EnableAD {
                        newData := ADData{}
                        if out, err := exec.Command("wbinfo", "-u").Output(); err == nil {
                                scanner := bufio.NewScanner(strings.NewReader(string(out)))
                                for scanner.Scan() {
                                        newData.Users = append(newData.Users, scanner.Text())
                                }
                        }
                        if out, err := exec.Command("wbinfo", "-g").Output(); err == nil {
                                scanner := bufio.NewScanner(strings.NewReader(string(out)))
                                for scanner.Scan() {
                                        newData.Groups = append(newData.Groups, scanner.Text())
                                }
                        }
                        sc.mu.Lock()
                        sc.adCache = newData
                        sc.mu.Unlock()
                }
                time.Sleep(interval)
        }
}

// isUserExcluded проверяет, нужно ли скрывать пользователя
func (sc *SambaCollector) isUserExcluded(username string) bool {
        if sc.cfg.Samba.UserFilter.ExcludeSystem && strings.HasSuffix(username, "$") {
                return true
        }
        for _, u := range sc.cfg.Samba.UserFilter.ExcludeList {
                if username == u {
                        return true
                }
        }
        return false
}

func (sc *SambaCollector) Describe(ch chan<- *prometheus.Desc) {
        // Описания можно оставить пустыми для автоматического Describe
}

// Collect основной метод сбора метрик
func (sc *SambaCollector) Collect(ch chan<- prometheus.Metric) {
        timer := prometheus.NewTimer(sc.scrapeDuration)
        defer timer.ObserveDuration()

        cmdPath := sc.cfg.Samba.SmbstatusPath
        if cmdPath == "" {
                cmdPath = "/usr/bin/smbstatus"
        }

        out, err := exec.Command(cmdPath, "--json").Output()
        up := 1.0
        if err != nil {
                up = 0.0
        }
        ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("samba_up", "Samba status", nil, nil), prometheus.GaugeValue, up)

        if err == nil {
                var data struct {
                        Sessions map[string]struct {
                                Username        string `json:"username"`
                                ProtocolVersion string `json:"session_dialect"`
                                RemoteMachine   string `json:"remote_machine"`
                                SessionID       string `json:"session_id"`
                        } `json:"sessions"`
                        Locks map[string]interface{} `json:"locks"`
                }
                if err := json.Unmarshal(out, &data); err == nil {
                        if sc.cfg.Samba.Collectors.EnableSessions {
                                for _, s := range data.Sessions {
                                        if s.Username != "" && !sc.isUserExcluded(s.Username) {
                                                desc := prometheus.NewDesc("samba_session_info", "Active sessions",
                                                        []string{"user", "ip", "protocol", "session_id"}, nil)
                                                ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, 1,
                                                        s.Username, s.RemoteMachine, s.ProtocolVersion, s.SessionID)
                                        }
                                }
                        }
                        ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("samba_locked_files_total", "Locks count", nil, nil), prometheus.GaugeValue, float64(len(data.Locks)))
                }
        }

        // Сбор сетевых метрик из /proc/net/dev
        if sc.cfg.Samba.Collectors.EnablePerf {
                if file, err := os.Open("/proc/net/dev"); err == nil {
                        scanner := bufio.NewScanner(file)
                        for scanner.Scan() {
                                f := strings.Fields(scanner.Text())
                                if len(f) > 10 && (strings.HasPrefix(f[0], "eth") || strings.HasPrefix(f[0], "en")) {
                                        dev := strings.Trim(f[0], ":")
                                        rx, _ := strconv.ParseFloat(f[1], 64)
                                        tx, _ := strconv.ParseFloat(f[9], 64)
                                        ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("samba_net_rx", "RX bytes", []string{"dev"}, nil), prometheus.CounterValue, rx, dev)
                                        ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("samba_net_tx", "TX bytes", []string{"dev"}, nil), prometheus.CounterValue, tx, dev)
                                }
                        }
                        file.Close()
                }
        }

        sc.mu.RLock()
        defer sc.mu.RUnlock()

        // Вывод данных шар из кэша
        for name, s := range sc.shareCache {
                ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("samba_share_used_bytes", "Used", []string{"share"}, nil), prometheus.GaugeValue, s.UsedBytes, name)
                ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("samba_share_available_bytes", "Free", []string{"share"}, nil), prometheus.GaugeValue, s.AvailableBytes, name)
                ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("samba_share_capacity_bytes", "Total", []string{"share"}, nil), prometheus.GaugeValue, s.TotalCapacity, name)
        }

        // Вывод данных AD
        if sc.cfg.Samba.Collectors.EnableAD {
                for _, u := range sc.adCache.Users {
                        ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("samba_ad_user", "AD User", []string{"name"}, nil), prometheus.GaugeValue, 1, u)
                }
                for _, g := range sc.adCache.Groups {
                        ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("samba_ad_group", "AD Group", []string{"name"}, nil), prometheus.GaugeValue, 1, g)
                }
        }
}
