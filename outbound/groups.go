package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/wolf-joe/go-ipset/ipset"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/utils"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
)

type IGroup interface {
	Match(req *dns.Msg) bool
	IsFallback() bool
	Handle(req *dns.Msg) *dns.Msg
	PostProcess(req *dns.Msg, resp *dns.Msg)
	Start(resolver dns.Handler)
	Stop()
	Name() string
	String() string
}

func BuildGroups(globalConf *config.Conf) (map[string]IGroup, error) {
	groups := make(map[string]IGroup, len(globalConf.Groups))
	// check non-repeatable flag
	seenGFWList, seenFallback := false, false
	for _, conf := range globalConf.Groups {
		if conf.Fallback && seenFallback {
			return nil, errors.New("only one group can be fallback group")
		}
		if conf.IsSetGFWList() && seenGFWList {
			return nil, errors.New("only one group can use gfw list mode")
		}
		if conf.Fallback {
			seenFallback = true
		}
		if conf.IsSetGFWList() {
			seenGFWList = true
		}
	}
	// build groups
	for name, conf := range globalConf.Groups {
		g := &groupImpl{
			name:        name,
			fallback:    conf.Fallback,
			matcher:     nil,
			gfwList:     nil,
			gfwListURL:  conf.GFWListURL,
			noCookie:    conf.NoCookie,
			withECS:     nil,
			callers:     nil,
			concurrent:  conf.Concurrent,
			proxy:       nil,
			fastestIP:   conf.FastestV4,
			tcpPingPort: conf.TCPPingPort,
			ipSet:       nil,
			stopCh:      make(chan struct{}),
			stopped:     make(chan struct{}),
		}
		// read rules
		text := strings.Join(conf.Rules, "\n")
		g.matcher = matcher.NewABPByText(text)
		if filename := conf.RulesFile; filename != "" {
			m, err := matcher.NewABPByFile(filename, false)
			if err != nil {
				return nil, fmt.Errorf("read rules file %q failed: %w", filename, err)
			}
			g.matcher.Extend(m)
		}
		// gfw list
		if conf.GFWListFile != "" {
			m, err := matcher.NewABPByFile(conf.GFWListFile, true)
			if err != nil {
				return nil, fmt.Errorf("build gfw list failed: %w", err)
			}
			atomic.StorePointer(&g.gfwList, unsafe.Pointer(m))
		}
		if len(conf.Rules) == 0 && conf.RulesFile == "" && !conf.IsSetGFWList() {
			if seenFallback {
				return nil, fmt.Errorf("empty rule for group %s", name)
			}
			logrus.Warnf("set group %s as fallback group", name)
			seenFallback = true
			g.fallback = true
		}
		// ecs
		if conf.ECS != "" {
			ecs, err := utils.ParseECS(conf.ECS)
			if err != nil {
				return nil, fmt.Errorf("parse ecs %q failed: %w", conf.ECS, err)
			}
			logrus.Debugf("set ecs(%s) for group %s", conf.ECS, err)
			g.withECS = ecs
		}
		// proxy
		if conf.Socks5 != "" {
			dialer, err := proxy.SOCKS5("tcp", conf.Socks5, nil, proxy.Direct)
			if err != nil {
				return nil, fmt.Errorf("build socks5 proxy %q failed: %w", conf.Socks5, err)
			}
			logrus.Debugf("set proxy(%s) for group %s", conf.Socks5, name)
			g.proxy = dialer
		}
		// caller
		var callers []Caller
		for _, addr := range conf.DNS {
			network := "udp"
			if strings.HasSuffix(addr, "/tcp") {
				addr, network = addr[:len(addr)-4], "tcp"
			}
			if addr != "" {
				if !strings.Contains(addr, ":") {
					addr += ":53"
				}
				callers = append(callers, NewDNSCaller(addr, network, g.proxy))
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
				callers = append(callers, NewDoTCaller(addr, serverName, g.proxy))
			}
		}
		for _, addr := range conf.DoH { // dns over https服务器
			caller, err := NewDoHCallerV2(addr, g.proxy)
			if err != nil {
				return nil, fmt.Errorf("build doh caller %s failed: %w", addr, err)
			}
			callers = append(callers, caller)
		}
		g.callers = callers
		// ipset
		if conf.IPSet != "" {
			is, err := ipset.New(conf.IPSet, "hash:ip", &ipset.Params{Timeout: conf.IPSetTTL})
			if err != nil {
				return nil, fmt.Errorf("build ipset %q failed: %w", conf.IPSet, err)
			}
			g.ipSet = is
		}
		groups[name] = g
	}

	return groups, nil
}

var (
	_ IGroup = &groupImpl{}
)

type groupImpl struct {
	name     string
	fallback bool

	matcher    *matcher.ABPlus
	gfwList    unsafe.Pointer // type: *matcher.ABPlus
	gfwListURL string

	noCookie bool              // 是否删除请求中的cookie
	withECS  *dns.EDNS0_SUBNET // 是否在请求中附加ECS信息

	callers    []Caller
	concurrent bool
	proxy      proxy.Dialer

	fastestIP   bool // 是否对响应中的IP地址进行测速，找出ping值最低的IP地址
	tcpPingPort int  // 是否使用tcp ping

	ipSet *ipset.IPSet // 将响应中的IPv4地址加入ipset

	stopCh  chan struct{}
	stopped chan struct{}
}

func (g *groupImpl) Name() string     { return g.name }
func (g *groupImpl) String() string   { return "group_" + g.Name() }
func (g *groupImpl) IsFallback() bool { return g.fallback }

func (g *groupImpl) Match(req *dns.Msg) bool {
	domain := ""
	if len(req.Question) > 0 {
		domain = req.Question[0].Name
	}
	if domain == "" {
		return false
	}

	if match, _ := g.matcher.Match(domain); match {
		return true
	}
	if ptr := atomic.LoadPointer(&g.gfwList); ptr != nil {
		if match, _ := (*matcher.ABPlus)(ptr).Match(domain); match {
			return true
		}
	}
	return false
}

func (g *groupImpl) Handle(req *dns.Msg) *dns.Msg {
	// 预处理请求
	if g.noCookie || g.withECS != nil {
		req = req.Copy()
		if g.noCookie {
			utils.RemoveEDNSCookie(req)
		}
		if g.withECS != nil {
			utils.SetDefaultECS(req, g.withECS)
		}
	}

	if !g.concurrent && !g.fastestIP {
		// 依次请求上游DNS
		for _, caller := range g.callers {
			resp, err := caller.Call(req)
			if err != nil {
				logrus.Warnf("group %s call %s failed: %+v", g.name, caller, err)
				continue
			}
			return resp
		}
		return nil
	}

	// 并发请求上游DNS
	chLen := len(g.callers)
	respCh := make(chan *dns.Msg, chLen)
	for _, caller := range g.callers {
		go func(caller Caller) {
			resp, err := caller.Call(req)
			if err == nil {
				respCh <- resp
			} else {
				logrus.Warnf("group %s call %s failed: %+v", g.name, caller, err)
				respCh <- nil
			}
		}(caller)
	}
	// 处理响应
	var qType uint16
	if len(req.Question) > 0 {
		qType = req.Question[0].Qtype
	}
	if (qType == dns.TypeA || qType == dns.TypeAAAA) && g.fastestIP {
		// 测速并返回最快ip
		return g.fastestResp(qType, respCh, chLen)
	}
	// 无需测速，只需返回第一个不为nil的DNS响应
	for i := 0; i < chLen; i++ {
		if resp := <-respCh; resp != nil {
			return resp
		}
	}
	return nil
}

func (g *groupImpl) fastestResp(qType uint16, respCh chan *dns.Msg, chLen int) *dns.Msg {
	const (
		maxGoNum    = 15 // 最大并发量
		pingTimeout = 500 * time.Millisecond
	)
	// 从resp ch中提取所有IP地址，并建立IP地址到resp的映射
	allIP := make([]string, 0, maxGoNum)
	respMap := make(map[string]*dns.Msg, maxGoNum)
	var firstResp *dns.Msg // 最早抵达的msg，当测速失败时返回该响应
	for i := 0; i < chLen; i++ {
		resp := <-respCh
		if resp == nil {
			continue
		}
		if firstResp == nil {
			firstResp = resp
		}
		for _, answer := range resp.Answer {
			var ip string
			switch rr := answer.(type) {
			case *dns.A:
				if qType == dns.TypeA {
					ip = rr.A.String()
				}
			case *dns.AAAA:
				if qType == dns.TypeAAAA {
					ip = rr.AAAA.String()
				}
			}
			if ip != "" {
				allIP = append(allIP, ip)
				if _, exists := respMap[ip]; !exists {
					respMap[ip] = resp
					if len(respMap) >= maxGoNum {
						goto doPing
					}
				}
			}
		}
	}
doPing:
	switch len(respMap) {
	case 0: // 没有任何IP地址
		return firstResp
	case 1: // 只有一个IPv4地址
		for _, resp := range respMap {
			return resp
		}
	}
	fastestIP, cost, err := utils.FastestPingIP(allIP, g.tcpPingPort, pingTimeout)
	if err != nil {
		return firstResp
	}
	logrus.Debugf("fastest ip of %s: %s(%dms)", allIP, fastestIP, cost)
	msg := respMap[fastestIP]
	// 删除msg内除fastestIP之外的其它IP记录
	for i := 0; i < len(msg.Answer); i++ {
		switch rr := msg.Answer[i].(type) {
		case *dns.A:
			if qType == dns.TypeA && rr.A.String() != fastestIP {
				goto delThis
			}
		case *dns.AAAA:
			if qType == dns.TypeAAAA && rr.AAAA.String() != fastestIP {
				goto delThis
			}
		}
		continue
	delThis:
		msg.Answer = append(msg.Answer[:i], msg.Answer[i+1:]...)
		i--
	}
	return msg
}

func (g *groupImpl) PostProcess(_ *dns.Msg, resp *dns.Msg) {
	if resp == nil || g.ipSet == nil {
		return
	}
	for _, answer := range resp.Answer {
		if a, ok := answer.(*dns.A); ok {
			if err := g.ipSet.Add(a.A.String(), g.ipSet.Timeout); err != nil {
				logrus.Warnf("add %s to ipset<%s> failed: %+v", a.A, g.ipSet.Name, err)
			}
		}
	}
}

func (g *groupImpl) grabGFWList() *matcher.ABPlus {
	if g.gfwListURL == "" {
		return nil
	}
	client := new(http.Client)
	client.Timeout = 10 * time.Second
	if g.proxy != nil {
		wrap := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return g.proxy.Dial(network, addr)
		}
		client.Transport = &http.Transport{DialContext: wrap}
	}
	// todo 自闭环解析dns
	req, _ := http.NewRequest("GET", g.gfwListURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		logrus.Warnf("get gfw list %q failed: %+v", g.gfwListURL, err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		logrus.Warnf("get gfw list %q failed, status_code: %d", g.gfwListURL, resp.StatusCode)
		return nil
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Warnf("read gfw list %q failed, error: %+v", g.gfwListURL, err)
		return nil
	}
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	if _, err = base64.StdEncoding.Decode(data, dst); err != nil {
		logrus.Warnf("decode gfw list %q failed, error: %+v", g.gfwListURL, err)
		return nil
	}
	return matcher.NewABPByText(string(dst))
}

func (g *groupImpl) Start(resolver dns.Handler) {
	for _, caller := range g.callers {
		caller.Start(resolver)
	}
	lastSuccess := time.Unix(0, 0)
	tick := time.NewTicker(time.Minute)
	go func() {
		for {
			select {
			case <-tick.C:
				if time.Since(lastSuccess).Hours() < 1 {
					// every hour
					continue
				}
				if m := g.grabGFWList(); m != nil {
					atomic.StorePointer(&g.gfwList, unsafe.Pointer(m))
					lastSuccess = time.Now()
				}
			case <-g.stopCh:
				close(g.stopped)
				tick.Stop()
				return
			}
		}
	}()
}

func (g *groupImpl) Stop() {
	logrus.Debugf("stop group %s", g)
	for _, caller := range g.callers {
		caller.Exit()
	}
	close(g.stopCh)
	<-g.stopped
	logrus.Debugf("stop group %s success", g)
}
