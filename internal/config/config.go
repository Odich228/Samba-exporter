package config

import (
        "os"
        "gopkg.in/yaml.v3"
)

type Config struct {
        Server struct {
                ListenAddress string `yaml:"listen_address"`
        } `yaml:"server"`
        Samba struct {
                ConfigPath    string `yaml:"config_path"`
                SmbstatusPath string `yaml:"smbstatus_path"`
                Intervals     struct {
                        SizeScan string `yaml:"size_scan"`
                        AdUpdate string `yaml:"ad_update"`
                } `yaml:"intervals"`
                Collectors struct {
                        EnableDu       bool `yaml:"enable_du"`
                        EnableSessions bool `yaml:"enable_sessions"`
                        EnableLocks    bool `yaml:"enable_locks"`
                        EnablePerf     bool `yaml:"enable_perf"`
                        EnableAD       bool `yaml:"enable_ad"`
                } `yaml:"collectors"`
                UserFilter struct {
                        ExcludeSystem bool     `yaml:"exclude_system"`
                        ExcludeList   []string `yaml:"exclude_list"`
                } `yaml:"user_filter"`
        } `yaml:"samba"`
}

func Load(path string) (*Config, error) {
        var cfg Config
        cfgData, err := os.ReadFile(path)
        if err != nil {
                return nil, err
        }
        err = yaml.Unmarshal(cfgData, &cfg)
        return &cfg, err
}
