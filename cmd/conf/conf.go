package conf

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	log "github.com/Sirupsen/logrus"
	"github.com/janeczku/go-ipset/ipset"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/core/common"
	"github.com/wolf-joe/ts-dns/core/context"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/inbound"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/outbound"
	"golang.org/x/net/proxy"
)

// 自定义查询日志的输出格式
type queryFormatter struct {
	log.TextFormatter
	ignoreQTypes []string
	ignoreHosts  bool
	ignoreCache  bool
}

// 和inbound/server.go中Handler.LogQuery的行为强关联
func (f *queryFormatter) Format(entry *log.Entry) ([]byte, error) {
	var ignore []byte
	for _, qType := range f.ignoreQTypes {
		if entry.Data[context.QTypeKey] == qType {
			return ignore, nil
		}
	}
	if f.ignoreHosts && entry.Message == "hit hosts" {
		return ignore, nil
	}
	if f.ignoreCache && entry.Message == "hit cache" {
		return ignore, nil
	}
	return f.TextFormatter.Format(entry)
}

// Group 配置文件中每个groups section对应的结构
type Group struct {
	ECS         string
	NoCookie    bool `toml:"no_cookie"`
	Socks5      string
	IPSet       string
	IPSetTTL    int `toml:"ipset_ttl"`
	DNS         []string
	DoT         []string
	DoH         []string
	Concurrent  bool
	FastestV4   bool `toml:"fastest_v4"`
	TCPPingPort int  `toml:"tcp_ping_port"`
	Rules       []string
	RulesFile   string `toml:"rules_file"`
}

// GenIPSet 读取ipset配置并打包成IPSet对象
func (conf *Group) GenIPSet() (ipSet *ipset.IPSet, err error) {
	if conf.IPSet != "" {
		param := &ipset.Params{Timeout: conf.IPSetTTL}
		ipSet, err = ipset.New(conf.IPSet, "hash:ip", param)
		if err != nil {
			return nil, err
		}
		return ipSet, nil
	}
	return nil, nil
}

// GenCallers 读取dns配置并打包成Caller对象
func (conf *Group) GenCallers() (callers []outbound.Caller) {
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
	for _, addr := range conf.DoH { // dns over https服务器
		if caller, err := outbound.NewDoHCaller(addr, dialer); err != nil {
			log.Errorf("parse doh server error: %v", err)
		} else {
			callers = append(callers, caller)
		}
	}
	return
}

// Cache 配置文件中cache section对应的结构
type Cache struct {
	Size   int
	MinTTL int `toml:"min_ttl"`
	MaxTTL int `toml:"max_ttl"`
}

// QueryLog 配置文件中query_log section对应的结构
type QueryLog struct {
	File         string
	IgnoreQTypes []string `toml:"ignore_qtypes"`
	IgnoreHosts  bool     `toml:"ignore_hosts"`
	IgnoreCache  bool     `toml:"ignore_cache"`
}

// GenLogger 读取logger配置并打包成Logger对象
func (conf *QueryLog) GenLogger() (logger *log.Logger, err error) {
	logger = log.New()
	if conf.File == "/dev/null" {
		logger.SetOutput(ioutil.Discard)
	} else if conf.File != "" {
		file, err := os.OpenFile(conf.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		logger.SetOutput(file)
	}
	logger.SetFormatter(&queryFormatter{ignoreQTypes: conf.IgnoreQTypes,
		ignoreHosts: conf.IgnoreHosts, ignoreCache: conf.IgnoreCache})
	return logger, nil
}

// Conf 配置文件总体结构
type Conf struct {
	Listen        string
	GFWList       string
	GFWb64        bool `toml:"gfwlist_b64"`
	CNIP          string
	Logger        *QueryLog `toml:"query_log"`
	HostsFiles    []string  `toml:"hosts_files"`
	Hosts         map[string]string
	Cache         *Cache
	Groups        map[string]*Group
	DisableIPv6   bool     `toml:"disable_ipv6"`
	DisableQTypes []string `toml:"disable_qtypes"`
}

// SetDefault 为部分字段默认配置
func (conf *Conf) SetDefault() {
	if conf.Listen == "" {
		conf.Listen = ":53"
	}
	if conf.GFWList == "" {
		conf.GFWList = "gfwlist.txt"
	}
	if conf.CNIP == "" {
		conf.CNIP = "cnip.txt"
	}
}

// GenCache 根据cache section里的配置生成cache实例
func (conf *Conf) GenCache() *cache.DNSCache {
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

// GenHostsReader 读取hosts section里的hosts记录、hosts_files里的hosts文件路径，生成hosts实例列表
func (conf *Conf) GenHostsReader() (readers []hosts.Reader) {
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

// GenGroups 读取groups section里的配置，生成inbound.Group map
func (conf *Conf) GenGroups() (groups map[string]*inbound.Group, err error) {
	groups = map[string]*inbound.Group{}
	// 读取每个域名组的配置信息
	for name, group := range conf.Groups {
		inboundGroup := &inbound.Group{
			Callers: group.GenCallers(), Concurrent: group.Concurrent,
			FastestV4: group.FastestV4, TCPPingPort: group.TCPPingPort,
			NoCookie: group.NoCookie,
		}
		if inboundGroup.Concurrent {
			log.Warnln("enable concurrent dns in group " + name)
		}
		if inboundGroup.FastestV4 {
			log.Warnln("find fastest ipv4 in group " + name)
		}
		if inboundGroup.ECS, err = common.ParseECS(group.ECS); err != nil {
			return nil, err
		}
		log.Debugf("ecs conf: %v", inboundGroup.ECS)
		// 读取匹配规则
		inboundGroup.Matcher, err = matcher.NewABPByFile(group.RulesFile, false)
		if err != nil {
			return nil, err
		}
		inboundGroup.Matcher.Extend(matcher.NewABPByText(strings.Join(group.Rules, "\n")))
		// 读取IPSet配置
		if inboundGroup.IPSet, err = group.GenIPSet(); err != nil {
			return nil, err
		}
		groups[name] = inboundGroup
	}
	return groups, nil
}

// NewHandler 从toml文件里读取ts-dns的配置并打包为Handler。如err不为空，则在返回前会输出相应错误信息
func NewHandler(filename string) (handler *inbound.Handler, err error) {
	config := Conf{Cache: &Cache{}, Logger: &QueryLog{}, GFWb64: true}
	if _, err = toml.DecodeFile(filename, &config); err != nil {
		log.WithField("file", filename).Errorf("read config error: %v", err)
		return nil, err
	}
	config.SetDefault()
	// 初始化handler
	handler = &inbound.Handler{Mux: new(sync.RWMutex), Listen: config.Listen}
	// 从listen中分离监听地址和协议
	if i := strings.Index(config.Listen, "/"); i != -1 {
		handler.Listen, handler.Network = config.Listen[:i], config.Listen[i+1:]
	}
	handler.DisableIPv6 = config.DisableIPv6
	if handler.DisableIPv6 {
		log.Warn("disable ipv6 resolve")
	}
	handler.DisableQTypes = map[string]bool{}
	for _, qType := range config.DisableQTypes {
		if qType = strings.TrimSpace(qType); qType != "" {
			handler.DisableQTypes[strings.ToUpper(qType)] = true
		}
	}
	// 读取gfwlist
	if handler.GFWMatcher, err = matcher.NewABPByFile(config.GFWList, config.GFWb64); err != nil {
		log.WithField("file", config.GFWList).Errorf("read gfwlist error: %v", err)
		return nil, err
	}
	// 读取cnip
	if handler.CNIP, err = cache.NewRamSetByFile(config.CNIP); err != nil {
		log.WithField("file", config.CNIP).Errorf("read cnip error: %v", err)
		return nil, err
	}
	// 读取groups
	if handler.Groups, err = config.GenGroups(); err != nil {
		log.Errorf("read group config error: %v", err)
		return nil, err
	}
	handler.HostsReaders = config.GenHostsReader()
	handler.Cache = config.GenCache()
	// 读取Logger
	if handler.QueryLogger, err = config.Logger.GenLogger(); err != nil {
		log.Errorf("create query logger error: %v", err)
		return nil, err
	}
	// 检测配置有效性
	if !handler.IsValid() {
		return nil, fmt.Errorf("")
	}
	return
}
