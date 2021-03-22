package model

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/janeczku/go-ipset/ipset"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/core/common"
	"github.com/wolf-joe/ts-dns/core/inbound"
	"github.com/wolf-joe/ts-dns/core/utils"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/outbound"
	"golang.org/x/net/proxy"
)

func newDNSCache(conf CacheConf) *cache.DNSCache {
	size := cache.DefaultSize
	minTTL := cache.DefaultMinTTL
	maxTTL := cache.DefaultMaxTTL
	if conf.Size != 0 {
		size = conf.Size
	}
	if conf.MinTTL != 0 {
		minTTL = time.Duration(conf.MinTTL) * time.Second
	}
	if conf.MaxTTL != 0 {
		maxTTL = time.Duration(conf.MaxTTL) * time.Second
	}
	return cache.NewDNSCache(size, minTTL, maxTTL)
}

func newLogCfg(ctx context.Context, conf *QueryLog) (*inbound.LogConfig, error) {
	var closer io.WriteCloser
	if conf.File == "/dev/null" { // 丢弃查询日志
		closer = &wrapCloser{Writer: ioutil.Discard}
	} else if conf.File != "" { // 查询日志写入到文件
		file, err := os.OpenFile(conf.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			utils.CtxError(ctx, "open file %q error: %s", conf.File, err)
			return nil, err
		}
		closer = file
	}
	return inbound.NewLogConfig(closer, conf.IgnoreQTypes, conf.IgnoreHosts, conf.IgnoreCache), nil
}

func newIPSet(ctx context.Context, name string, ttl int) (*ipset.IPSet, error) {
	if name != "" {
		param := &ipset.Params{Timeout: ttl}
		val, err := ipset.New(name, "hash:ip", param)
		if err != nil {
			utils.CtxError(ctx, "new ipset %q error: %s", name, err)
			return nil, err
		}
		return val, nil
	}
	return nil, nil
}

// 接受类似"1.1.1.1:53/udp"的配置
func newDNSCaller(server string, dialer proxy.Dialer) (*outbound.DNSCaller, error) {
	port, network := 53, "udp"
	if strings.Contains(server, "/") {
		parts := strings.Split(server, "/")
		server = parts[0]
		if len(parts) > 1 {
			network = strings.ToLower(parts[1])
		}
	}
	if network != "udp" && network != "tcp" {
		return nil, errors.New("unknown network: " + network)
	}
	var err error
	if strings.Contains(server, ":") {
		parts := strings.Split(server, ":")
		server = parts[0]
		if len(parts) > 1 {
			port, err = strconv.Atoi(parts[1])
		}
	}
	if err != nil {
		return nil, err
	}
	if server == "" {
		return nil, errors.New("empty server")
	}
	server += fmt.Sprintf(":%d", port)
	return outbound.NewDNSCaller(server, network, dialer), nil
}

// 接受类似"1.1.1.1:853@domain.com"的配置
func newDoTCaller(server string, dialer proxy.Dialer) (*outbound.DNSCaller, error) {
	port, domain := 853, ""
	if strings.Contains(server, "@") {
		parts := strings.Split(server, "@")
		server = parts[0]
		if len(parts) > 1 {
			domain = strings.ToLower(parts[1])
		}
	}
	if domain == "" {
		return nil, errors.New("empty domain")
	}
	var err error
	if strings.Contains(server, ":") {
		parts := strings.Split(server, ":")
		server = parts[0]
		if len(parts) > 1 {
			port, err = strconv.Atoi(parts[1])
		}
	}
	if err != nil {
		return nil, err
	}
	if server == "" {
		return nil, errors.New("empty server")
	}
	server += fmt.Sprintf(":%d", port)
	return outbound.NewDoTCaller(server, domain, dialer), nil
}

func newCallers(ctx context.Context, socks5 string, dns, dot, doh []string) ([]outbound.Caller, error) {
	// 初始化socks5代理
	var dialer proxy.Dialer
	var err error
	if socks5 != "" {
		dialer, _ = proxy.SOCKS5("tcp", socks5, nil, proxy.Direct)
	}
	var caller outbound.Caller
	var ans []outbound.Caller
	for _, server := range dns {
		caller, err = newDNSCaller(server, dialer)
		if err != nil {
			utils.CtxError(ctx, "parse dns %q error: %s", server, err)
			return nil, err
		}
		ans = append(ans, caller)
	}
	for _, server := range dot {
		caller, err = newDoTCaller(server, dialer)
		if err != nil {
			utils.CtxError(ctx, "parse dot %q error: %s", server, err)
			return nil, err
		}
		ans = append(ans, caller)
	}
	for _, server := range doh {
		caller, err = outbound.NewDoHCallerV2(ctx, server, dialer)
		if err != nil {
			utils.CtxError(ctx, "parse doh %q error: %s", server, err)
			return nil, err
		}
		ans = append(ans, caller)
	}
	return ans, nil
}

func newGroup(ctx context.Context, name string, conf *Group) (*inbound.Group, error) {
	priority := 255
	// 读取域名分组配置
	rule, err := matcher.NewABPByFile(conf.RulesFile, false)
	if err != nil {
		utils.CtxError(ctx, "read rules file %q error: %s", conf.RulesFile, err)
		return nil, err
	}
	rule.Extend(matcher.NewABPByText(strings.Join(conf.Rules, "\n")))
	if conf.RulesFile == "" && len(conf.RulesFile) == 0 {
		rule = matcher.NewABPByText("*")
		priority = math.MaxInt32
	}
	// 读取dns服务器配置
	callers, err := newCallers(ctx, conf.Socks5, conf.DNS, conf.DoT, conf.DoH)
	if err != nil {
		return nil, err
	}
	// 读取group配置
	group := inbound.NewGroup(name, rule, callers)
	group.Priority = priority
	group.IPSet, err = newIPSet(ctx, conf.IPSet, conf.IPSetTTL)
	if err != nil {
		return nil, err
	}
	group.WithECS, err = common.ParseECS(conf.ECS)
	if err != nil {
		utils.CtxError(ctx, "parse ecs %q error: %s", conf.ECS, err)
		return nil, err
	}
	group.NoCookie = conf.NoCookie
	group.Concurrent = conf.Concurrent
	if conf.FastestV4 {
		group.WithFastestIP(conf.TCPPingPort)
	}
	return group, nil
}

// 将listen配置（如":53/udp"）拆分成ip+port和network两部分
func parseListen(listen string) (string, string) {
	network := ""
	if i := strings.Index(listen, "/"); i != -1 {
		listen, network = listen[:i], listen[i+1:]
	}
	ip, port := listen, ":53"
	if i := strings.Index(listen, ":"); i != -1 {
		ip, port = listen[:i], listen[i:]
	}

	return ip + port, network
}

// 读取配置，创建一个DNSServer
func newDNSServer(ctx context.Context, conf Conf) (*inbound.DNSServer, error) {
	// 读取域名组配置
	groups := make(map[string]*inbound.Group, len(conf.Groups))
	for name, groupConf := range conf.Groups {
		group, err := newGroup(ctx, name, groupConf)
		if err != nil {
			return nil, err
		}
		groups[name] = group
	}
	// 读取日志配置
	logCfg, err := newLogCfg(ctx, conf.Logger)
	if err != nil {
		return nil, err
	}
	// 读取服务器配置
	addr, network := parseListen(conf.Listen)
	svc := inbound.NewDNSServer(addr, network, groups, logCfg)
	svc.Cache = newDNSCache(conf.Cache)
	if conf.DisableIPv6 {
		conf.DisableQTypes = append(conf.DisableQTypes, "AAAA")
	}
	svc.SetDisableQTypes(conf.DisableQTypes)
	// 读取hosts
	svc.Hosts = make([]hosts.Reader, 0, len(conf.HostsFiles)+1)
	for _, file := range conf.HostsFiles {
		var reader hosts.Reader
		if reader, err = hosts.NewReaderByFile(file, 0); err != nil {
			utils.CtxWarn(ctx, "read hosts %s: %s", file, err)
		} else {
			svc.Hosts = append(svc.Hosts, reader)
		}
	}
	if len(conf.Hosts) > 0 {
		lines := make([]string, 0, len(conf.Hosts))
		for hostname, ip := range conf.Hosts {
			lines = append(lines, ip+" "+hostname)
		}
		text := strings.Join(lines, "\n")
		svc.Hosts = append(svc.Hosts, hosts.NewReaderByText(text))
	}

	if err = compatibleOld(ctx, conf, svc); err != nil {
		return nil, err
	}
	return svc, nil
}

// NewDNSServerFromText 从文本中读取配置
func NewDNSServerFromText(ctx context.Context, text string) (*inbound.DNSServer, error) {
	conf := Conf{Logger: &QueryLog{}}
	if _, err := toml.Decode(text, &conf); err != nil {
		utils.CtxError(ctx, "decode toml error: %s", err)
		return nil, err
	}
	return newDNSServer(ctx, conf)
}

// NewDNSServerFromFile 从文件中读取配置
func NewDNSServerFromFile(ctx context.Context, file string) (*inbound.DNSServer, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		utils.CtxError(ctx, "read file %q error: %s", file, err)
		return nil, err
	}
	return NewDNSServerFromText(ctx, string(data))
}

// 兼容老逻辑
func compatibleOld(ctx context.Context, conf Conf, svc *inbound.DNSServer) error {
	if conf.CNIP == "" && conf.GFWList == "" {
		return nil // 不走老逻辑
	}
	groupClean, groupDirty := svc.GetGroup("clean"), svc.GetGroup("dirty")
	if groupClean == nil || groupDirty == nil {
		return errors.New("group clean/dirty not found")
	}
	gfw, err := matcher.NewABPByFile(conf.GFWList, conf.GFWb64)
	if err != nil {
		utils.CtxError(ctx, "read gfwlist %q: %s", conf.GFWList, err)
		return err
	}
	gfwRed := inbound.NewDomainRedirector(gfw, inbound.DomainRedRuleIfMatch, groupDirty)
	cnIP, err := cache.NewRamSetByFile(conf.CNIP)
	if err != nil {
		utils.CtxError(ctx, "read cnip %q: %s", conf.CNIP, err)
		return err
	}
	cnIPRed := inbound.NewIPRedirector(cnIP, inbound.IPRedRuleIfFind, gfwRed)
	groupClean.Next = cnIPRed
	return nil
}

type wrapCloser struct{ io.Writer }

// Close do nothing
func (c *wrapCloser) Close() error { return nil }
