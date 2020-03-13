package main

import (
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	DNS "github.com/wolf-joe/ts-dns/DNSCaller"
	"github.com/wolf-joe/ts-dns/GFWList"
	"github.com/wolf-joe/ts-dns/Hosts"
	ipset "github.com/wolf-joe/ts-dns/IPSet"
	"github.com/wolf-joe/ts-dns/TSDNS"
	"github.com/wolf-joe/ts-dns/cache"
	"golang.org/x/net/proxy"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

var VERSION = "Unknown"

var tomlConfig tomlStruct

type tomlStruct struct {
	Listen     string
	GFWFile    string   `toml:"gfwlist"`
	HostsFiles []string `toml:"hosts_files"`
	Hosts      map[string]string
	Cache      cacheStruct
	GroupMap   map[string]groupStruct `toml:"groups"`
}

type groupStruct struct {
	Socks5    string
	IPSetName string `toml:"ipset"`
	IPSetTTL  int    `toml:"ipset_ttl"`
	DNS       []string
	DoT       []string
	DoH       []string
	Rules     []string
}

type cacheStruct struct {
	Size   int
	MinTTL int `toml:"min_ttl"`
	MaxTTL int `toml:"max_ttl"`
}

func initConfig() (config *TSDNS.Config) {
	// 读取命令行参数
	var cfgPath string
	var version bool
	flag.StringVar(&cfgPath, "c", "ts-dns.toml", "config file path")
	flag.BoolVar(&version, "v", false, "show version and exit")
	flag.Parse()
	if version { // 显示版本号
		fmt.Println(VERSION)
		os.Exit(0)
	}
	// 读取配置文件
	if _, err := toml.DecodeFile(cfgPath, &tomlConfig); err != nil {
		log.Fatalf("[CRITICAL] read tomlConfig error: %v\n", err)
	}
	config = &TSDNS.Config{Listen: tomlConfig.Listen, GroupMap: map[string]TSDNS.Group{}}
	if config.Listen == "" {
		config.Listen = ":53"
	}
	// 读取gfwlist
	var err error
	if tomlConfig.GFWFile == "" {
		tomlConfig.GFWFile = "gfwlist.txt"
	}
	if config.GFWChecker, err = GFWList.NewCheckerByFn(tomlConfig.GFWFile, true); err != nil {
		log.Fatalf("[CRITICAL] read GFWFile error: %v\n", err)
	}
	// 读取Hosts列表
	var lines []string
	for hostname, ip := range tomlConfig.Hosts {
		lines = append(lines, ip+" "+hostname)
	}
	if len(lines) > 0 {
		text := strings.Join(lines, "\n")
		config.HostsReaders = append(config.HostsReaders, Hosts.NewTextReader(text))
	}
	// 读取Hosts文件列表。reloadTick为0代表不自动重载hosts文件
	for _, filename := range tomlConfig.HostsFiles {
		if reader, err := Hosts.NewFileReader(filename, 0); err != nil {
			log.Printf("[WARNING] read Hosts error: %v\n", err)
		} else {
			config.HostsReaders = append(config.HostsReaders, reader)
		}
	}
	// 读取每个域名组的配置信息
	for name, group := range tomlConfig.GroupMap {
		// 读取socks5代理地址
		var dialer proxy.Dialer
		if group.Socks5 != "" {
			dialer, _ = proxy.SOCKS5("tcp", group.Socks5, nil, proxy.Direct)
		}
		// 为每个dns服务器创建Caller对象
		var callers []DNS.Caller
		for _, addr := range group.DNS { // TCP/UDP服务器
			useTcp := false
			if strings.HasSuffix(addr, "/tcp") {
				addr, useTcp = addr[:len(addr)-4], true
			}
			if addr != "" {
				if !strings.Contains(addr, ":") {
					addr += ":53"
				}
				if useTcp {
					callers = append(callers, &DNS.TCPCaller{Address: addr, Dialer: dialer})
				} else {
					callers = append(callers, &DNS.UDPCaller{Address: addr, Dialer: dialer})
				}
			}
		}
		for _, addr := range group.DoT { // dns over tls服务器，格式为ip:port@serverName
			var serverName string
			if arr := strings.Split(addr, "@"); len(arr) != 2 {
				continue
			} else {
				addr, serverName = arr[0], arr[1]
			}
			if addr != "" {
				if !strings.Contains(addr, ":") {
					addr += ":853"
				}
				if serverName != "" {
					callers = append(callers, DNS.NewTLSCaller(addr, dialer, serverName, false))
				}
			}
		}
		dohReg := regexp.MustCompile(`^https://.+/dns-query$`)
		for _, addr := range group.DoH { // dns over https服务器，格式为https://domain/dns-query
			if dohReg.MatchString(addr) {
				callers = append(callers, &DNS.DoHCaller{Url: addr, Dialer: dialer})
			}
		}
		tsGroup := TSDNS.Group{Callers: callers}
		// 读取匹配规则
		tsGroup.Matcher = TSDNS.NewDomainMatcher(group.Rules)
		// 读取IPSet名称和ttl
		if group.IPSetName != "" {
			if group.IPSetTTL > 0 {
				tsGroup.IPSetTTL = group.IPSetTTL
			}
			tsGroup.IPSet, err = ipset.New(group.IPSetName, "hash:ip", &ipset.Params{})
			if err != nil {
				log.Fatalf("[CRITICAL] create ipset error: %v\n", err)
			}
		}
		config.GroupMap[name] = tsGroup
	}
	// 读取cache配置
	cacheSize, minTTL, maxTTL := 4096, time.Minute, 24*time.Hour
	if tomlConfig.Cache.Size != 0 {
		cacheSize = tomlConfig.Cache.Size
	}
	if tomlConfig.Cache.MinTTL != 0 {
		minTTL = time.Second * time.Duration(tomlConfig.Cache.MinTTL)
	}
	if tomlConfig.Cache.MaxTTL != 0 {
		maxTTL = time.Second * time.Duration(tomlConfig.Cache.MaxTTL)
	}
	if maxTTL < minTTL {
		maxTTL = minTTL
	}
	config.Cache = cache.NewDNSCache(cacheSize, minTTL, maxTTL)
	// 检测配置有效性
	if len(config.GroupMap) <= 0 || len(config.GroupMap["clean"].Callers) <= 0 || len(config.GroupMap["dirty"].Callers) <= 0 {
		log.Fatalln("[CRITICAL] DNS of clean/dirty group cannot be empty")
	}
	return
}
