package main

import (
	"./TTLMap"
	"flag"
	"github.com/BurntSushi/toml"
	"github.com/go-redis/redis"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"log"
	"strings"
)

var suffixMap = map[string]string{}
var groupS5Map = map[string]proxy.Dialer{}
var hostsMap = map[string]string{}
var gfwList *GFWList
var config tsDNSConfig

type tsDNSConfig struct {
	Listen      string
	GFWListFile string   `toml:"gfwlist"`
	HostsFiles  []string `toml:"hosts_files"`
	Hosts       map[string]string
	Redis       redisConfig
	Groups      map[string]groupConfig
}

type redisConfig struct {
	Host     string
	Password string
	DB       int
}

type groupConfig struct {
	Socks5 string
	DNS    []string
	Suffix []string
}

func initConfig() {
	// 读取配置文件
	var cfgPath string
	flag.StringVar(&cfgPath, "c", "ts-dns.toml", "Config File Path")
	flag.Parse()
	if _, err := toml.DecodeFile(cfgPath, &config); err != nil {
		log.Printf("[ERROR] read config error: %v\n", err)
		// 缺少配置则载入默认配置
		defaultDNSMap := map[string][]string{
			"clean": {"119.29.29.29:53", "223.5.5.5:53"},
			"dirty": {"208.67.222.222:5353", "176.103.130.130:5353"},
		}
		suffixMap["google.com."] = "dirty"
		suffixMap["twimg.com."] = "dirty"
		suffixMap["quoracdn.net"] = "dirty"
		config.Groups = map[string]groupConfig{}
		config.Listen = ":53"
		for groupName, defaultDNS := range defaultDNSMap {
			if group, ok := config.Groups[groupName]; !ok || len(group.DNS) <= 0 {
				config.Groups[groupName] = groupConfig{DNS: defaultDNS}
			}
		}
	}
	// 读取gfwlist
	var err error
	if config.GFWListFile != "" {
		if gfwList, err = new(GFWList).Init(config.GFWListFile); err != nil {
			log.Fatalf("[CRITICAL] read gfwlist error: %v\n", err)
		}
	}
	// 读取hosts
	for _, hostsFile := range config.HostsFiles {
		if raw, err := ioutil.ReadFile(hostsFile); err != nil {
			log.Printf("[WARNING] read hosts error: %v\n", err)
		} else {
			for _, line := range strings.Split(string(raw), "\n") {
				line = strings.Trim(line, " \t\r")
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				splitter := func(r rune) bool { return r == ' ' || r == '\t' }
				if arr := strings.FieldsFunc(line, splitter); len(arr) >= 2 {
					if ip, domain := arr[0], arr[1]; domain[len(domain)-1] != '.' {
						hostsMap[domain+"."] = ip
					} else {
						hostsMap[domain] = ip
					}
				}
			}
		}
	}
	for domain, ip := range config.Hosts {
		if domain != "" && domain[len(domain)-1] != '.' {
			hostsMap[domain+"."] = ip
		} else if domain != "" {
			hostsMap[domain] = ip
		}
	}
	// 读取suffix和socks5代理地址，并为DNS地址加上默认端口
	for groupName, group := range config.Groups {
		for _, suffix := range group.Suffix {
			if suffix != "" && suffix[len(suffix)-1] != '.' {
				suffixMap[suffix+"."] = groupName
			} else if suffix != "" {
				suffixMap[suffix] = groupName
			}
		}
		if group.Socks5 != "" {
			s5dialer, _ := proxy.SOCKS5("tcp", group.Socks5, nil, proxy.Direct)
			groupS5Map[groupName] = s5dialer
		}
		for i, addr := range group.DNS {
			if addr != "" && !strings.Contains(addr, ":") {
				group.DNS[i] = addr + ":53"
			}
		}
	}
	// 读取redis
	if rds := config.Redis; rds.Host != "" {
		groupCache = redis.NewClient(&redis.Options{Addr: rds.Host, Password: rds.Password, DB: rds.DB})
		if _, err := groupCache.(*redis.Client).Ping().Result(); err != nil {
			log.Fatalf("[CRITICAL] connect redis error: %v\n", err)
		} else {
			log.Printf("[WARNING] connect redis://%s/%d success\n", rds.Host, rds.DB)
		}
	} else {
		groupCache = new(TTLMap.TTLMap).Init(60)
	}
}
