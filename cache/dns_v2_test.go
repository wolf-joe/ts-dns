package cache

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
	"testing"
)

func TestNewDNSCache(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("z.cn.", dns.TypeA)
	c, err := NewDNSCache2(&config.Conf{Cache: config.CacheConf{
		Size: 0, MinTTL: 0, MaxTTL: 0,
	}})
	assert.Nil(t, err)

	resp := new(dns.Msg)
	rr, _ := dns.NewRR("z.cn. 0 IN A 1.1.1.1")
	resp.Answer = append(resp.Answer, rr)
	rr, _ = dns.NewRR("z.cn. 0 IN A 1.1.1.2")
	resp.Answer = append(resp.Answer, rr)
	c.Set(req, resp)
	assert.Nil(t, c.Get(req))

	err = c.ReloadConfig(&config.Conf{Cache: config.CacheConf{
		Size: 1024, MinTTL: 60, MaxTTL: 3600,
	}})
	assert.Nil(t, err)
	c.Set(req, resp)
	assert.NotNil(t, c.Get(req))
	t.Log(c.Get(req))
}

func BenchmarkNewDNSCache(b *testing.B) {
	req := new(dns.Msg)
	req.SetQuestion("z.cn.", dns.TypeA)
	c, err := NewDNSCache2(&config.Conf{Cache: config.CacheConf{
		Size: 1024, MinTTL: 60, MaxTTL: 3600,
	}})
	assert.Nil(b, err)

	resp := new(dns.Msg)
	rr, _ := dns.NewRR("z.cn. 0 IN A 1.1.1.1")
	resp.Answer = append(resp.Answer, rr)
	rr, _ = dns.NewRR("z.cn. 0 IN A 1.1.1.2")
	resp.Answer = append(resp.Answer, rr)

	for i := 0; i < b.N; i++ {
		c.Set(req, resp)
		assert.NotNil(b, c.Get(req))
	}
}
