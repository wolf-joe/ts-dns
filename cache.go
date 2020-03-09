package main

import (
	"github.com/miekg/dns"
	"strconv"
	"time"
)

const (
	CacheSize   = 4096
	CacheMinTTL = 60
	CacheMaxTTL = 86400
)

var dnsCache = new(TTLMap).Init(60)

func getDNSCache(question dns.Question) *dns.Msg {
	cacheKey := question.Name + strconv.FormatInt(int64(question.Qtype), 10)
	if cacheHit, ok := dnsCache.Get(cacheKey); ok {
		return cacheHit.(*dns.Msg)
	}
	return nil
}

func setDNSCache(question dns.Question, r *dns.Msg) {
	if r == nil || len(dnsCache.itemMap) >= CacheSize {
		return
	}
	cacheKey := question.Name + strconv.FormatInt(int64(question.Qtype), 10)
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
