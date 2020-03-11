package main

import (
	"./GFWList"
	"./Hosts"
	"./IPSet"
	"./TTLMap"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/go-redis/redis"
	"golang.org/x/net/proxy"
	"log"
	"os"
	"strings"
	"time"
)

var VERSION = "Unknown"

var suffixMap = map[string]string{}
var config tsDNSConfig
var hostsReaders []Hosts.Reader

type tsDNSConfig struct {
	Listen     string
	GFWFile    string `toml:"gfwlist"`
	GFWChecker *GFWList.DomainChecker
	HostsFiles []string `toml:"hosts_files"`
	Hosts      map[string]string
	Redis      redisConfig
	Groups     map[string]groupConfig
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
	if config.GFWFile == "" {
		config.GFWFile = "gfwlist.txt"
	}
	if config.GFWChecker, err = GFWList.NewCheckerByFn(config.GFWFile, true); err != nil {
		log.Fatalf("[CRITICAL] read gfwlist error: %v\n", err)
	}
	// 读取Hosts
	var lines []string
	for hostname, ip := range config.Hosts {
		lines = append(lines, ip+" "+hostname)
	}
	if len(lines) > 0 {
		text := strings.Join(lines, "\n")
		hostsReaders = append(hostsReaders, Hosts.NewTextReader(text))
	}
	// 读取Hosts文件。reloadTick为0代表不自动重载hosts文件
	for _, filename := range config.HostsFiles {
		if reader, err := Hosts.NewFileReader(filename, 0); err != nil {
			log.Printf("[WARNING] read hosts error: %v\n", err)
		} else {
			hostsReaders = append(hostsReaders, reader)
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
		groupCache = TTLMap.NewMap(time.Minute)
	}
	// 检测配置有效性
	if len(config.Groups) <= 0 || len(config.Groups["clean"].DNS) <= 0 || len(config.Groups["dirty"].DNS) <= 0 {
		log.Fatalln("[CRITICAL] DNS of clean/dirty group cannot be empty")
	}
}
