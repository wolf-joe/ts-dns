package cache

import (
	"github.com/miekg/dns"
	"github.com/valyala/fastrand"
	"github.com/wolf-joe/ts-dns/core/common"
	"strconv"
	"time"
)

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
	for i := 0; i < len(r.Answer); i++ { // 倒计时ttl
		r.Answer[i].Header().Ttl = uint32(ttl)
	}
	// 打乱ip响应顺序
	first := uint32(len(r.Answer))
	for ; first > 0; first-- {
		if t := r.Answer[first-1].Header().Rrtype; t != dns.TypeA && t != dns.TypeAAAA {
			break
		}
	}
	ips := r.Answer[first:] // 切片不重新分配内存，修改ips相当于直接修改r.Answer
	if len(ips) > 1 {
		for i := uint32(len(ips) - 1); i > 0; i-- {
			j := fastrand.Uint32n(i + 1)
			ips[i], ips[j] = ips[j], ips[i]
		}
	}
	return r
}

// Get 获取DNS响应缓存，响应的ttl为倒计时形式
func (cache *DNSCache) Get(request *dns.Msg) *dns.Msg {
	question := request.Question[0]
	cacheKey := question.Name + strconv.FormatInt(int64(question.Qtype), 10)
	if subnet := common.FormatECS(request); subnet != "" {
		cacheKey += "." + subnet
	}
	if cacheHit, ok := cache.ttlMap.Get(cacheKey); ok {
		r := cacheHit.(*cacheEntry).Get()
		return r
	}
	return nil
}

// Set 设置DNS响应缓存，缓存的ttl由minTTL、maxTTL、响应本身的ttl共同决定
func (cache *DNSCache) Set(request *dns.Msg, r *dns.Msg) {
	question := request.Question[0]
	if cache.ttlMap.Len() >= cache.size || r == nil || len(r.Answer) <= 0 {
		return
	}
	cacheKey := question.Name + strconv.FormatInt(int64(question.Qtype), 10)
	if subnet := common.FormatECS(request); subnet != "" {
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
		r.Answer[i].Header().Ttl = uint32(ex.Seconds())
	}
	entry := &cacheEntry{r: r, expire: time.Now().Add(ex)}
	cache.ttlMap.Set(cacheKey, entry, ex)
}

// NewDNSCache 生成一个DNS响应缓存器实例
func NewDNSCache(size int, minTTL, maxTTL time.Duration) (c *DNSCache) {
	c = &DNSCache{size: size, minTTL: minTTL, maxTTL: maxTTL}
	c.ttlMap = NewTTLMap(time.Minute)
	return
}
