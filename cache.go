package main

import (
	"./TTLMap"
	"github.com/go-redis/redis"
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
var groupCache interface{}

func getDNSCache(question dns.Question) *dns.Msg {
	cacheKey := question.Name + strconv.FormatInt(int64(question.Qtype), 10)
	if cacheHit, ok := dnsCache.Get(cacheKey); ok {
		return cacheHit.(*dns.Msg)
	}
	return nil
}

func setDNSCache(question dns.Question, r *dns.Msg) {
	if dnsCache.Len() >= CacheSize || r == nil || len(r.Answer) <= 0 {
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

func getGroupCache(domain string) (group string) {
	var cacheHit interface{}
	switch groupCache.(type) {
	case *redis.Client:
		// get redis key时忽略错误，因为作者无法区分"key不存在"和其它错误
		cacheHit, _ = groupCache.(*redis.Client).Get(domain).Result()
	default:
		cacheHit, _ = groupCache.(*TTLMap.TTLMap).Get(domain)
	}
	if cacheHit != nil {
		return cacheHit.(string)
	}
	return ""
}

func setGroupCache(domain string, group string) (err error) {
	ex := time.Hour * 24
	switch groupCache.(type) {
	case *redis.Client:
		return groupCache.(*redis.Client).Set(domain, group, ex).Err()
	default:
		if groupCache.(*TTLMap.TTLMap).Len() < CacheSize {
			groupCache.(*TTLMap.TTLMap).Set(domain, group, ex)
		}
		return nil
	}
}
