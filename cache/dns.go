package cache

import (
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

// DNSCache DNS响应缓存器
type DNSCache struct {
	ttlMap *TTLMap
	size   int
	minTTL time.Duration
	maxTTL time.Duration
}

// dns响应的包裹，用以实现动态ttl
type cacheEntry struct {
	r      *dns.Msg
	expire time.Time
}

func (entry *cacheEntry) Get() *dns.Msg {
	var ttl int64
	if ttl = entry.expire.Unix() - time.Now().Unix(); ttl < 0 {
		return nil
	}
	r := entry.r.Copy()
	for i := 0; i < len(r.Answer); i++ {
		r.Answer[i].Header().Ttl = uint32(ttl)
	}
	return r
}

// Get 获取DNS响应缓存，响应的ttl为倒计时形式
func (cache *DNSCache) Get(request *dns.Msg) *dns.Msg {
	question, extra := request.Question[0], request.Extra
	cacheKey := question.Name + strconv.FormatInt(int64(question.Qtype), 10)
	if subnet := getSubnet(extra); subnet != "" {
		cacheKey += "." + subnet
	}
	if cacheHit, ok := cache.ttlMap.Get(cacheKey); ok {
		return cacheHit.(*cacheEntry).Get()
	}
	return nil
}

// Set 设置DNS响应缓存，缓存的ttl由minTTL、maxTTL、响应本身的ttl共同决定
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
	for i := 0; i < len(r.Answer); i++ {
		r.Answer[i].Header().Ttl = uint32(ex)
	}
	entry := &cacheEntry{r: r, expire: time.Now().Add(ex)}
	cache.ttlMap.Set(cacheKey, entry, ex)
}

func NewDNSCache(size int, minTTL, maxTTL time.Duration) (c *DNSCache) {
	c = &DNSCache{size: size, minTTL: minTTL, maxTTL: maxTTL}
	c.ttlMap = NewTTLMap(time.Minute)
	return
}
