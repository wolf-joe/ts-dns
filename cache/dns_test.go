package cache

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCacheEntry(t *testing.T) {
	resp := &dns.Msg{}
	rr, _ := dns.NewRR("ip.cn. 0 IN A 1.1.1.1") // 实际ttl为-1
	resp.Answer = append(resp.Answer, rr)
	entry := cacheEntry{r: resp, expire: time.Now().Add(time.Second)} // ttl覆盖为1
	assert.True(t, entry.Get().Answer[0].Header().Ttl > 0)
	time.Sleep(time.Second * 2)
	assert.Nil(t, entry.Get())
}

func TestGetDNSCache(t *testing.T) {
	request1, request2, resp := &dns.Msg{}, &dns.Msg{}, &dns.Msg{}
	rr, _ := dns.NewRR("ip.cn. 0 IN A 1.1.1.1")
	resp.Answer = append(resp.Answer, rr)
	request1.SetQuestion("ip.cn.", dns.TypeA)
	request2.SetQuestion("ip.cn.", dns.TypeAAAA)
	opt := &dns.EDNS0_SUBNET{Address: []byte("1.1.1.1"), SourceNetmask: 24}
	request2.Extra = append(request2.Extra, &dns.OPT{Option: []dns.EDNS0{opt}})

	// 缓存立即失效
	cache := NewDNSCache(1, 0, 0)
	cache.Set(request1, resp)
	assert.True(t, cache.Get(request1) == nil)
	// 缓存未立即失效
	cache = NewDNSCache(1, time.Second, time.Second)
	cache.Set(request1, resp)
	assert.True(t, cache.Get(request1) != nil)
	// 插入失败
	cache.Set(request2, resp)
	assert.True(t, cache.ttlMap.Len() == 1)
	// 1秒钟后缓存失效
	time.Sleep(time.Second)
	assert.True(t, cache.Get(request1) == nil)
	assert.True(t, cache.ttlMap.Len() == 0)
	cache.Set(request2, resp)
	assert.True(t, cache.ttlMap.Len() == 1)
	assert.True(t, cache.Get(request2) != nil)
}

func TestTTLRewrite(t *testing.T) {
	rr1, _ := dns.NewRR("ip.cn. 0 IN A 1.1.1.1")
	rr2, _ := dns.NewRR("ip.cn. 0 IN A 1.1.1.2")
	req, resp := &dns.Msg{}, &dns.Msg{Answer: []dns.RR{rr1, rr2}}
	req.SetQuestion("ip.cn.", dns.TypeA)
	cache := NewDNSCache(1, time.Minute, time.Hour*24)
	cache.Set(req, resp)
	assert.NotEqual(t, resp.Answer[0].Header().Ttl, uint32(0))
	// 顺便测试random record order
	cache.Get(req)
}
