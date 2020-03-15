package main

import (
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	log "github.com/Sirupsen/logrus"
	"github.com/janeczku/go-ipset/ipset"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/inbound"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/outbound"
	"golang.org/x/net/proxy"
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
	CNIPFile   string   `toml:"cnip"`
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

func initConfig() (c *inbound.Handler) {
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
		log.WithField("file", cfgPath).Fatalf("read config error: %v", err)
	}
	c = &inbound.Handler{Listen: tomlConfig.Listen, GroupMap: map[string]inbound.Group{}}
	if c.Listen == "" {
		c.Listen = ":53"
	}
	// 读取gfwlist
	var err error
	if tomlConfig.GFWFile == "" {
		tomlConfig.GFWFile = "gfwlist.txt"
	}
	if c.GFWMatcher, err = matcher.NewABPByFile(tomlConfig.GFWFile, true); err != nil {
		log.WithField("file", tomlConfig.GFWFile).Fatalf("read gfwlist error: %v", err)
	}
	// 读取cnip
	if tomlConfig.CNIPFile == "" {
		tomlConfig.CNIPFile = "cnip.txt"
	}
	if c.CNIPs, err = cache.NewRamSetByFn(tomlConfig.CNIPFile); err != nil {
		log.WithField("file", tomlConfig.CNIPFile).Fatalf("read cnip error: %v", err)
	}
	// 读取Hosts列表
	var lines []string
	for hostname, ip := range tomlConfig.Hosts {
		lines = append(lines, ip+" "+hostname)
	}
	if len(lines) > 0 {
		text := strings.Join(lines, "\n")
		c.HostsReaders = append(c.HostsReaders, hosts.NewTextReader(text))
	}
	// 读取Hosts文件列表。reloadTick为0代表不自动重载hosts文件
	for _, filename := range tomlConfig.HostsFiles {
		if reader, err := hosts.NewFileReader(filename, 0); err != nil {
			log.WithField("file", filename).Warnf("read hosts error: %v", err)
		} else {
			c.HostsReaders = append(c.HostsReaders, reader)
		}
	}
	// 读取每个域名组的配置信息
	for name, group := range tomlConfig.GroupMap {
		// 读取socks5代理地址
		var dialer proxy.Dialer
		if group.Socks5 != "" {
			dialer, _ = proxy.SOCKS5("tcp", group.Socks5, nil, proxy.Direct)
		}
		// 为每个出站dns服务器地址创建对应Caller对象
		var callers []outbound.Caller
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
					callers = append(callers, &outbound.TCPCaller{Address: addr, Dialer: dialer})
				} else {
					callers = append(callers, &outbound.UDPCaller{Address: addr, Dialer: dialer})
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
					callers = append(callers, outbound.NewTLSCaller(addr, dialer, serverName, false))
				}
			}
		}
		dohReg := regexp.MustCompile(`^https://.+/dns-query$`)
		for _, addr := range group.DoH { // dns over https服务器，格式为https://domain/dns-query
			if dohReg.MatchString(addr) {
				callers = append(callers, &outbound.DoHCaller{Url: addr, Dialer: dialer})
			}
		}
		tsGroup := inbound.Group{Callers: callers}
		// 读取匹配规则
		tsGroup.Matcher = matcher.NewABPByText(strings.Join(group.Rules, "\n"))
		// 读取IPSet名称和ttl
		if group.IPSetName != "" {
			if group.IPSetTTL > 0 {
				tsGroup.IPSetTTL = group.IPSetTTL
			}
			tsGroup.IPSet, err = ipset.New(group.IPSetName, "hash:ip", &ipset.Params{})
			if err != nil {
				log.Fatalf("create ipset error: %v", err)
			}
		}
		c.GroupMap[name] = tsGroup
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
	c.Cache = cache.NewDNSCache(cacheSize, minTTL, maxTTL)
	// 检测配置有效性
	if len(c.GroupMap) <= 0 || len(c.GroupMap["clean"].Callers) <= 0 || len(c.GroupMap["dirty"].Callers) <= 0 {
		log.Fatalf("dns of clean/dirty group cannot be empty")
	}
	return
}
