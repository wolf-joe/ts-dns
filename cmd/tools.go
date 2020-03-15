package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	log "github.com/Sirupsen/logrus"
	"github.com/fsnotify/fsnotify"
	"github.com/janeczku/go-ipset/ipset"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/inbound"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/outbound"
	"golang.org/x/net/proxy"
	"regexp"
	"strings"
	"sync"
	"time"
)

type tomlStruct struct {
	Listen     string
	GFWList    string   `toml:"gfwlist"`
	CNIP       string   `toml:"cnip"`
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

// 从配置文件里读取ts-dns的配置并打包。如err不为空，则在返回前会输出相应错误信息
func initHandler(filename string) (h *inbound.Handler, err error) {
	var config tomlStruct
	if _, err = toml.DecodeFile(filename, &config); err != nil {
		log.WithField("file", filename).Errorf("read config error: %v", err)
		return nil, err
	}
	// 默认配置
	if config.Listen == "" {
		config.Listen = ":53"
	}
	if config.GFWList == "" {
		config.GFWList = "gfwlist.txt"
	}
	if config.CNIP == "" {
		config.CNIP = "cnip.txt"
	}
	if config.Cache.Size == 0 {
		config.Cache.Size = 4096
	}
	if config.Cache.MinTTL == 0 {
		config.Cache.MinTTL = 60
	}
	if config.Cache.MaxTTL == 0 {
		config.Cache.MaxTTL = 86400
	}

	h = &inbound.Handler{Mux: new(sync.RWMutex), Listen: config.Listen, GroupMap: map[string]*inbound.Group{}}
	// 读取gfwlist
	if h.GFWMatcher, err = matcher.NewABPByFile(config.GFWList, true); err != nil {
		log.WithField("file", config.GFWList).Errorf("read gfwlist error: %v", err)
		return nil, err
	}
	// 读取cnip
	if h.CNIP, err = cache.NewRamSetByFn(config.CNIP); err != nil {
		log.WithField("file", config.CNIP).Errorf("read cnip error: %v", err)
		return nil, err
	}
	// 读取Hosts列表
	var lines []string
	for hostname, ip := range config.Hosts {
		lines = append(lines, ip+" "+hostname)
	}
	if len(lines) > 0 {
		text := strings.Join(lines, "\n")
		h.HostsReaders = append(h.HostsReaders, hosts.NewTextReader(text))
	}
	// 读取Hosts文件列表。reloadTick为0代表不自动重载hosts文件
	for _, filename := range config.HostsFiles {
		if reader, err := hosts.NewFileReader(filename, 0); err != nil {
			log.WithField("file", filename).Warnf("read hosts error: %v", err)
		} else {
			h.HostsReaders = append(h.HostsReaders, reader)
		}
	}
	// 读取每个域名组的配置信息
	for groupName, groupConf := range config.GroupMap {
		// 读取socks5代理地址
		var dialer proxy.Dialer
		if groupConf.Socks5 != "" {
			dialer, _ = proxy.SOCKS5("tcp", groupConf.Socks5, nil, proxy.Direct)
		}
		// 为每个出站dns服务器创建对应Caller对象
		var callers []outbound.Caller
		for _, addr := range groupConf.DNS { // TCP/UDP服务器
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
		for _, addr := range groupConf.DoT { // dns over tls服务器，格式为ip:port@serverName
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
		for _, addr := range groupConf.DoH { // dns over https服务器，格式为https://domain/dns-query
			if dohReg.MatchString(addr) {
				callers = append(callers, &outbound.DoHCaller{Url: addr, Dialer: dialer})
			}
		}
		group := &inbound.Group{Callers: callers}
		// 读取匹配规则
		group.Matcher = matcher.NewABPByText(strings.Join(groupConf.Rules, "\n"))
		// 读取IPSet配置
		if groupConf.IPSetName != "" {
			if groupConf.IPSetTTL > 0 {
				group.IPSetTTL = groupConf.IPSetTTL
			}
			group.IPSet, err = ipset.New(groupConf.IPSetName, "hash:ip", &ipset.Params{})
			if err != nil {
				log.Errorf("create ipset error: %v", err)
				return nil, err
			}
		}
		h.GroupMap[groupName] = group
	}
	// 读取cache配置
	minTTL := time.Duration(config.Cache.MinTTL) * time.Second
	maxTTL := time.Duration(config.Cache.MaxTTL) * time.Second
	h.Cache = cache.NewDNSCache(config.Cache.Size, minTTL, maxTTL)
	// 检测配置有效性
	if len(h.GroupMap) <= 0 || len(h.GroupMap["clean"].Callers) <= 0 || len(h.GroupMap["dirty"].Callers) <= 0 {
		log.Errorf("dns of clean/dirty group cannot be empty")
		return nil, fmt.Errorf("dns of clean/dirty group cannot be empty")
	}
	return
}

// 持续监测目标配置文件，如文件发生变动则尝试载入，载入成功后更新现有handler的配置
func autoReload(handle *inbound.Handler, filename string) {
	fields := log.Fields{"file": filename}
	// 创建监测器
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.WithFields(fields).Errorf("create watcher error: %v", err)
		return
	}
	defer func() {
		_ = watcher.Close()
		log.WithFields(fields).Errorf("file watcher closed")
	}()
	// 指定监测文件
	if err = watcher.Add(filename); err != nil {
		log.WithFields(fields).Errorf("watch file error: %v", err)
		return
	}
	// 接收文件事件
	for {
		select {
		case event, ok := <-watcher.Events: // 出现文件事件
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write { // 文件变动事件
				log.WithFields(fields).Warnf("file changed, reloading")
				if newHandler, err := initHandler(filename); err == nil {
					handle.Refresh(newHandler)
				}
			}
		case err, ok := <-watcher.Errors: // 出现错误
			if !ok {
				return
			}
			log.WithFields(fields).Errorf("watch error: %v", err)
		}
		time.Sleep(time.Second)
	}
}
