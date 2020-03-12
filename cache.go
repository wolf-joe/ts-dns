package main

import (
	"./TTLMap"
	"fmt"
	"github.com/miekg/dns"
	"strconv"
	"time"
)

const (
	CacheSize   = 4096
	CacheMinTTL = 60
	CacheMaxTTL = 86400
)

var dnsCache = TTLMap.NewMap(time.Minute)

// 获取dns请求或响应extra中的subnet字符串，格式为"Address/SourceNetmask"
func getSubnet(extra []dns.RR) string {
	for _, extra := range extra {
		switch extra.(type) {
		case *dns.OPT:
			for _, opt := range extra.(*dns.OPT).Option {
				switch opt.(type) {
				case *dns.EDNS0_SUBNET:
					subOpt := opt.(*dns.EDNS0_SUBNET)
					return fmt.Sprintf("%s/%d", subOpt.Address, subOpt.SourceNetmask)
				}
			}
		}
	}
	return ""
}

func getDNSCache(question dns.Question, extra []dns.RR) *dns.Msg {
	cacheKey := question.Name + strconv.FormatInt(int64(question.Qtype), 10)
	if subnet := getSubnet(extra); subnet != "" {
		cacheKey += "." + subnet
	}
	if cacheHit, ok := dnsCache.Get(cacheKey); ok {
		return cacheHit.(*dns.Msg)
	}
	return nil
}

func setDNSCache(question dns.Question, extra []dns.RR, r *dns.Msg) {
	if dnsCache.Len() >= CacheSize || r == nil || len(r.Answer) <= 0 {
		return
	}
	cacheKey := question.Name + strconv.FormatInt(int64(question.Qtype), 10)
	if subnet := getSubnet(extra); subnet != "" {
		cacheKey += "." + subnet
	}
	var ex uint32 = CacheMaxTTL
	for _, answer := range r.Answer {
		if ttl := answer.Header().Ttl; ttl < ex {
			ex = ttl
		}
	}
	if ex < CacheMinTTL {
		ex = CacheMinTTL
	}
	dnsCache.Set(cacheKey, r, time.Duration(ex)*time.Second)
}
