package inbound

import (
	"context"
	"fmt"
	"time"

	"github.com/janeczku/go-ipset/ipset"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/core/common"
	"github.com/wolf-joe/ts-dns/core/utils"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/outbound"
)

// Group 域名解析组，负责将DNS请求转发至上游DNS
type Group struct {
	name    string
	matcher matcher.DomainMatcher // 域名匹配规则

	NoCookie bool              // NoCookie 是否删除请求中的cookie
	WithECS  *dns.EDNS0_SUBNET // WithECS 是否在请求中附加ECS信息

	callers    []outbound.Caller // 上游DNS服务器
	Concurrent bool              // Concurrent 是否需要并发请求

	fastestIP   bool // 是否对响应中的IP地址进行测速，找出ping值最低的IP地址
	tcpPingPort int  // 是否使用tcp ping

	IPSet *ipset.IPSet // IPSet 将响应中的IP地址加入ipset
	Next  Handler      // Next 下一个DNS请求处理器
}

// NewGroup 初始化一个解析组。需要匹配规则、上游DNS
func NewGroup(name string, matcher matcher.DomainMatcher, callers []outbound.Caller) *Group {
	return &Group{name: name, matcher: matcher, callers: callers}
}

// WithFastestIP 处理DNS请求时只返回响应里ping值最低的IP地址。当tcpPingPort大于0时使用tcp ping
func (g *Group) WithFastestIP(tcpPingPort int) {
	g.fastestIP = true
	g.tcpPingPort = tcpPingPort
}

// Handle 处理DNS请求
func (g *Group) Handle(ctx context.Context, req, _ *dns.Msg) (resp *dns.Msg) {
	utils.CtxDebug(ctx, "handle by "+g.String())
	var recursive bool // 检测是否存在回环处理
	if ctx, recursive = recursiveDetect(ctx, g); recursive {
		utils.CtxError(ctx, "handle recursive")
		return resp
	}
	defer func(req *dns.Msg) {
		go g.add2IPSet(ctx, resp)
		if g.Next != nil {
			resp = g.Next.Handle(ctx, req, resp)
		}
	}(req)

	if g.NoCookie || g.WithECS != nil {
		// 预处理请求
		req = req.Copy()
		if g.NoCookie {
			common.RemoveEDNSCookie(req)
		}
		if g.WithECS != nil {
			common.SetDefaultECS(req, g.WithECS)
		}
	}

	if !g.Concurrent && !g.fastestIP {
		// 依次请求上游DNS
		for _, caller := range g.callers {
			resp, err := caller.Call(req)
			if err == nil {
				return resp
			}
			utils.CtxWarn(ctx, "query dns error: "+err.Error())
		}
		return nil
	}
	// 并发请求上游DNS
	chLen := len(g.callers)
	respCh := make(chan *dns.Msg, chLen)
	for _, caller := range g.callers {
		go func(c outbound.Caller) {
			resp, err := c.Call(req)
			if err == nil {
				respCh <- resp
			} else {
				utils.CtxWarn(ctx, "query dns error: "+err.Error())
				respCh <- nil
			}
		}(caller)
	}

	// 处理响应
	var qType uint16
	if len(req.Question) > 0 {
		qType = req.Question[0].Qtype
	}
	if !g.fastestIP || (qType != dns.TypeA && qType != dns.TypeAAAA) {
		// 无需测速，只需返回第一个不为nil的DNS响应
		for i := 0; i < chLen; i++ {
			if resp := <-respCh; resp != nil {
				return resp
			}
		}
		return nil
	}
	return g.fastestResp(ctx, qType, respCh, chLen)
}

// 寻找响应里ping值最低的IP地址
func (g *Group) fastestResp(ctx context.Context, qType uint16, respCh chan *dns.Msg, chLen int) *dns.Msg {
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
	fastestIP, cost, err := utils.FastestPingIP(ctx, allIP, g.tcpPingPort, pingTimeout)
	if err != nil {
		return firstResp
	}
	utils.CtxDebug(ctx, "fastest ip of %s: %s(%dms)", allIP, fastestIP, cost)
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

// 将响应中的IP地址加入ipset
func (g *Group) add2IPSet(ctx context.Context, resp *dns.Msg) {
	if resp == nil || g.IPSet == nil {
		return
	}
	for _, answer := range resp.Answer {
		if a, ok := answer.(*dns.A); ok {
			if err := g.IPSet.Add(a.A.String(), g.IPSet.Timeout); err != nil {
				utils.CtxWarn(ctx, "add %s to ipset %s error: %s", a.A, g.IPSet.Name, err)
			}
		}
	}
}

// String 描述自身
func (g *Group) String() string {
	return fmt.Sprintf("Group<%s,%d>", g.name, len(g.callers))
}

// Exit 停止服务
func (g *Group) Exit() {
	for _, caller := range g.callers {
		caller.Exit()
	}
}
