package TSDNS

import (
	"../TTLMap"
	"fmt"
	"github.com/miekg/dns"
	"strconv"
	"time"
)

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

type DNSCache struct {
	ttlMap *TTLMap.TTLMap
	size   int
	minTTL time.Duration
	maxTTL time.Duration
}

func (cache *DNSCache) Get(request *dns.Msg) *dns.Msg {
	question, extra := request.Question[0], request.Extra
	cacheKey := question.Name + strconv.FormatInt(int64(question.Qtype), 10)
	if subnet := getSubnet(extra); subnet != "" {
		cacheKey += "." + subnet
	}
	if cacheHit, ok := cache.ttlMap.Get(cacheKey); ok {
		return cacheHit.(*dns.Msg)
	}
	return nil
}

func (cache *DNSCache) Set(request *dns.Msg, r *dns.Msg) {
	question, extra := request.Question[0], request.Extra
	if cache.ttlMap.Len() >= cache.size || r == nil || len(r.Answer) <= 0 {
		return
	}
	cacheKey := question.Name + strconv.FormatInt(int64(question.Qtype), 10)
	if subnet := getSubnet(extra); subnet != "" {
		cacheKey += "." + subnet
	}
	var ex = cache.maxTTL
	for _, answer := range r.Answer {
		if ttl := time.Duration(answer.Header().Ttl) * time.Second; ttl < ex {
			ex = ttl
		}
	}
	if ex < cache.minTTL {
		ex = cache.minTTL
	}
	cache.ttlMap.Set(cacheKey, r, ex)
}

func NewDNSCache(size int, minTTL, maxTTL time.Duration) (cache *DNSCache) {
	cache = &DNSCache{size: size, minTTL: minTTL, maxTTL: maxTTL}
	cache.ttlMap = TTLMap.NewMap(time.Minute)
	return
}
