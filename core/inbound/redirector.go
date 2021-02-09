package inbound

import (
	"context"
	"fmt"
	"net"

	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/core/utils"
	"github.com/wolf-joe/ts-dns/matcher"
)

// IPRedRule IP重定向器规则
type IPRedRule int

const (
	// IPRedTypeIfFind 如果响应里出现匹配指定范围的ip地址
	IPRedTypeIfFind IPRedRule = iota
	// IPRedTypeIfNotFind 如果响应里未出现匹配指定范围的ip地址
	IPRedTypeIfNotFind
)

// IPRedirector 基于DNS响应中IP地址的重定向器
type IPRedirector struct {
	ramSet *cache.RamSet
	rule   IPRedRule
	next   Handler
}

// NewIPRedirector 创建一个重定向器
func NewIPRedirector(ramSet *cache.RamSet, rule IPRedRule, next Handler) *IPRedirector {
	return &IPRedirector{ramSet: ramSet, rule: rule, next: next}
}

// String 描述
func (red *IPRedirector) String() string {
	return fmt.Sprintf("IPRedirector<%d>", red.rule)
}

// Call 根据ip地址范围和规则决定是否转发至其它处理器
func (red *IPRedirector) Call(ctx context.Context, req, resp *dns.Msg) *dns.Msg {
	utils.CtxDebug(ctx, "call "+red.String())
	if red.next == nil {
		utils.CtxWarn(ctx, "next not set")
		return resp
	}
	var recursive bool
	if ctx, recursive = recursiveDetect(ctx, red); recursive {
		utils.CtxWarn(ctx, "handle recursive")
		return resp
	}
	var find bool
	for _, ans := range resp.Answer {
		var ip net.IP
		switch rr := ans.(type) {
		case *dns.A:
			ip = rr.A.To4()
		case *dns.AAAA:
			ip = rr.AAAA.To16()
		default:
			continue
		}
		if red.ramSet.Contain(ip) {
			find = true
			if red.rule == IPRedTypeIfFind {
				return red.next.Call(ctx, req, resp)
			}
		}
	}
	if !find && red.rule == IPRedTypeIfNotFind {
		return red.next.Call(ctx, req, resp)
	}
	return resp
}

// DomainRedRule 重定向器规则
type DomainRedRule int

const (
	// DomainRedRuleIfMatch 如果请求的域名匹配指定规则
	DomainRedRuleIfMatch DomainRedRule = iota
	// DomainRedRuleIfNotMatch 如果请求的域名匹配指定规则
	DomainRedRuleIfNotMatch
)

// DomainRedirector 基于DNS请求中目标域名的重定向器
type DomainRedirector struct {
	matcher matcher.DomainMatcher
	rule    DomainRedRule
	next    Handler
}

// NewDomainRedirector 创建一个重定向器
func NewDomainRedirector(matcher matcher.DomainMatcher, rule DomainRedRule, next Handler) *DomainRedirector {
	return &DomainRedirector{matcher: matcher, rule: rule, next: next}
}

// Call 根据请求域名和规则决定是否转发至其它处理器
func (red *DomainRedirector) Call(ctx context.Context, req, resp *dns.Msg) *dns.Msg {
	utils.CtxDebug(ctx, "call "+red.String())
	if red.next == nil {
		utils.CtxWarn(ctx, "next not set")
		return resp
	}
	var recursive bool
	if ctx, recursive = recursiveDetect(ctx, red); recursive {
		utils.CtxWarn(ctx, "handle recursive")
		return resp
	}
	for _, question := range req.Question {
		if match, ok := red.matcher.Match(question.Name); ok && match {
			if red.rule == DomainRedRuleIfMatch {
				return red.next.Call(ctx, req, resp)
			}
		} else {
			if red.rule == DomainRedRuleIfNotMatch {
				return red.next.Call(ctx, req, resp)
			}
		}
		break // only care about the first question
	}
	return resp
}

// String 描述
func (red *DomainRedirector) String() string {
	return fmt.Sprintf("DomainRedirector<%d>", red.rule)
}
