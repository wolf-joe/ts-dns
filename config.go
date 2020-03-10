package main

import (
	"./TTLMap"
	"./ipset"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/go-redis/redis"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

var VERSION = "Unknown"

var suffixMap = map[string]string{}
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
	Socks5    string
	Dialer    proxy.Dialer
	IPSetName string `toml:"ipset"`
	IPSetTTL  int    `toml:"ipset_ttl"`
	IPSet     *ipset.IPSet
	DNS       []string
	Suffix    []string
}

func initConfig() {
	// 读取配置文件
	var cfgPath string
	var version bool
	flag.StringVar(&cfgPath, "c", "ts-dns.toml", "config file path")
	flag.BoolVar(&version, "v", false, "show version and exit")
	flag.Parse()
	if version {
		fmt.Println(VERSION)
		os.Exit(0)
	}
	if _, err := toml.DecodeFile(cfgPath, &config); err != nil {
		log.Fatalf("[CRITICAL] read config error: %v\n", err)
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
	// 读取每个组的suffix、socks5、ipset，并为DNS地址加上默认端口
	for groupName, group := range config.Groups {
		for _, suffix := range group.Suffix {
			if suffix != "" && suffix[len(suffix)-1] != '.' {
				suffixMap[suffix+"."] = groupName
			} else if suffix != "" {
				suffixMap[suffix] = groupName
			}
		}
		if group.Socks5 != "" {
			group.Dialer, _ = proxy.SOCKS5("tcp", group.Socks5, nil, proxy.Direct)
			config.Groups[groupName] = group
		}
		for i, addr := range group.DNS {
			if addr != "" && !strings.Contains(addr, ":") {
				group.DNS[i] = addr + ":53"
			}
		}
		if group.IPSetName != "" {
			if group.IPSetTTL < 0 {
				group.IPSetTTL = 0
			}
			group.IPSet, err = ipset.New(group.IPSetName, "hash:ip", &ipset.Params{})
			if err != nil {
				log.Fatalf("[CRITICAL] create ipset error: %v\n", err)
			}
			config.Groups[groupName] = group
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
	// 检测配置有效性
	if len(config.Groups) <= 0 || len(config.Groups["clean"].DNS) <= 0 || len(config.Groups["dirty"].DNS) <= 0 {
		log.Fatalln("[CRITICAL] DNS of clean/dirty group cannot be empty")
	}
}
