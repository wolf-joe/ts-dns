package TSDNS

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

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
