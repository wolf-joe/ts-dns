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

type groupConf struct {
	Socks5     string
	IPSet      string
	IPSetTTL   int `toml:"ipset_ttl"`
	DNS        []string
	DoT        []string
	DoH        []string
	Concurrent bool
	Rules      []string
}

type cacheConf struct {
	Size   int
	MinTTL int `toml:"min_ttl"`
	MaxTTL int `toml:"max_ttl"`
}

type tomlConf struct {
	Listen     string
	GFWList    string
	CNIP       string
	HostsFiles []string `toml:"hosts_files"`
	Hosts      map[string]string
	Cache      *cacheConf
	Groups     map[string]*groupConf
}

// 根据配置生成cache实例
func (conf *tomlConf) genCache() *cache.DNSCache {
	if conf.Cache.Size == 0 {
		conf.Cache.Size = 4096
	}
	if conf.Cache.MinTTL == 0 {
		conf.Cache.MinTTL = 60
	}
	if conf.Cache.MaxTTL == 0 {
		conf.Cache.MaxTTL = 86400
	}
	minTTL := time.Duration(conf.Cache.MinTTL) * time.Second
	maxTTL := time.Duration(conf.Cache.MaxTTL) * time.Second
	return cache.NewDNSCache(conf.Cache.Size, minTTL, maxTTL)
}

// 根据配置生成hosts实例列表
func (conf *tomlConf) genHosts() (readers []hosts.Reader) {
	// 读取Hosts列表
	var lines []string
	for hostname, ip := range conf.Hosts {
		lines = append(lines, ip+" "+hostname)
	}
	if len(lines) > 0 {
		text := strings.Join(lines, "\n")
		readers = append(readers, hosts.NewReaderByText(text))
	}
	// 读取Hosts文件列表。reloadTick为0代表不自动重载hosts文件
	for _, filename := range conf.HostsFiles {
		if reader, err := hosts.NewReaderByFile(filename, 0); err != nil {
			log.WithField("file", filename).Warnf("read hosts error: %v", err)
		} else {
			readers = append(readers, reader)
		}
	}
	return
}

func (conf *groupConf) genCallers() (callers []outbound.Caller) {
	// 读取socks5代理地址
	var dialer proxy.Dialer
	if conf.Socks5 != "" {
		dialer, _ = proxy.SOCKS5("tcp", conf.Socks5, nil, proxy.Direct)
	}
	// 为每个出站dns服务器创建对应Caller对象
	for _, addr := range conf.DNS { // TCP/UDP服务器
		network := "udp"
		if strings.HasSuffix(addr, "/tcp") {
			addr, network = addr[:len(addr)-4], "tcp"
		}
		if addr != "" {
			if !strings.Contains(addr, ":") {
				addr += ":53"
			}
			callers = append(callers, outbound.NewDNSCaller(addr, network, dialer))
		}
	}
	for _, addr := range conf.DoT { // dns over tls服务器，格式为ip:port@serverName
		var serverName string
		if arr := strings.Split(addr, "@"); len(arr) != 2 {
			continue
		} else {
			addr, serverName = arr[0], arr[1]
		}
		if addr != "" && serverName != "" {
			if !strings.Contains(addr, ":") {
				addr += ":853"
			}
			callers = append(callers, outbound.NewDoTCaller(addr, serverName, dialer))
		}
	}
	dohReg := regexp.MustCompile(`^https://.+/dns-query$`)
	for _, addr := range conf.DoH { // dns over https服务器，格式为https://domain/dns-query
		if dohReg.MatchString(addr) {
			callers = append(callers, outbound.NewDoHCaller(addr, dialer))
		}
	}
	return
}

// 从配置文件里读取ts-dns的配置并打包。如err不为空，则在返回前会输出相应错误信息
func initHandler(filename string) (h *inbound.Handler, err error) {
	var config tomlConf
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

	h = &inbound.Handler{Mux: new(sync.RWMutex), Listen: config.Listen, Groups: map[string]*inbound.Group{}}
	// 读取gfwlist
	if h.GFWMatcher, err = matcher.NewABPByFile(config.GFWList, true); err != nil {
		log.WithField("file", config.GFWList).Errorf("read gfwlist error: %v", err)
		return nil, err
	}
	// 读取cnip
	if h.CNIP, err = cache.NewRamSetByFile(config.CNIP); err != nil {
		log.WithField("file", config.CNIP).Errorf("read cnip error: %v", err)
		return nil, err
	}
	h.HostsReaders = config.genHosts()
	h.Cache = config.genCache()
	// 读取每个域名组的配置信息
	for gName, gConf := range config.Groups {
		// 读取匹配规则
		group := &inbound.Group{Callers: gConf.genCallers(), Concurrent: gConf.Concurrent}
		if group.Concurrent {
			log.Warnln("enable dns concurrent in group " + gName)
		}
		group.Matcher = matcher.NewABPByText(strings.Join(gConf.Rules, "\n"))
		// 读取IPSet配置
		if gConf.IPSet != "" {
			param := &ipset.Params{Timeout: gConf.IPSetTTL}
			group.IPSet, err = ipset.New(gConf.IPSet, "hash:ip", param)
			if err != nil {
				log.Errorf("create ipset error: %v", err)
				return nil, err
			}
		}
		h.Groups[gName] = group
	}
	// 检测配置有效性
	if len(h.Groups) <= 0 || len(h.Groups["clean"].Callers) <= 0 || len(h.Groups["dirty"].Callers) <= 0 {
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
