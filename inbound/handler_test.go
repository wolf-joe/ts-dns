package inbound

import (
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/outbound"
	"github.com/wolf-joe/ts-dns/utils"
	"testing"
)

func buildReq(name string, qType uint16) *dns.Msg {
	return &dns.Msg{Question: []dns.Question{{
		Name: name, Qtype: qType,
	}}}
}

func Test_handlerImpl_ServeDNS(t *testing.T) {
}

func TestNewHandler(t *testing.T) {
	h, err := NewHandler(config.Conf{
		HostsFiles:    nil,
		Hosts:         nil,
		Cache:         config.CacheConf{},
		Groups:        map[string]config.Group{"default": {}},
		DisableIPv6:   false,
		DisableQTypes: nil,
		Redirectors:   nil,
		Listen:        "",
	})
	assert.Nil(t, err)
	assert.NotNil(t, h)

	err = h.ReloadConfig(config.Conf{
		HostsFiles:    nil,
		Hosts:         nil,
		Cache:         config.CacheConf{},
		Groups:        map[string]config.Group{"default": {}},
		DisableIPv6:   false,
		DisableQTypes: nil,
		Redirectors:   nil,
		Listen:        "",
	})
	assert.Nil(t, err)
	rw := utils.NewFakeRespWriter()
	h.ServeDNS(rw, buildReq("ip.cn", dns.TypeA))
	assert.NotNil(t, rw.Msg)
	h.Stop()
	h.Stop()

	_, err = NewHandler(config.Conf{
		HostsFiles:    []string{"not_exists.txt"},
		Hosts:         nil,
		Cache:         config.CacheConf{},
		Groups:        nil,
		DisableIPv6:   false,
		DisableQTypes: nil,
		Redirectors:   nil,
		Listen:        "",
	})
	assert.NotNil(t, err)
	t.Log(err)
}

func Test_newHandle(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	defaultConf := config.Conf{
		HostsFiles: nil,
		Hosts: map[string]string{
			"z.cn": "1.1.1.1", "v6.cn": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		},
		Cache:         config.CacheConf{},
		Groups:        map[string]config.Group{"fallback": {}},
		DisableIPv6:   false,
		DisableQTypes: nil,
		Redirectors:   nil,
		Listen:        "",
	}
	t.Run("hosts", func(t *testing.T) {
		conf := defaultConf
		h, err := newHandle(conf)
		assert.Nil(t, err)
		assert.NotNil(t, h)

		rw := utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("z.cn", dns.TypeA))
		assert.NotNil(t, rw.Msg)
		assert.NotNil(t, rw.Msg.Answer)

		rw = utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("v6.cn", dns.TypeAAAA))
		t.Log(rw.Msg.String())
		assert.NotNil(t, rw.Msg)
		assert.NotNil(t, rw.Msg.Answer)
	})
	t.Run("disable", func(t *testing.T) {
		conf := defaultConf
		conf.DisableQTypes = []string{"???"}
		_, err := newHandle(conf)
		assert.NotNil(t, err)
		t.Log(err)

		conf.DisableQTypes = []string{"A"}
		conf.DisableIPv6 = true
		h, err := newHandle(conf)
		assert.Nil(t, err)
		assert.NotNil(t, h)
		rw := utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("z.cn", dns.TypeA))
		assert.NotNil(t, rw.Msg)
		assert.Nil(t, rw.Msg.Answer)

		rw = utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("v6.cn", dns.TypeAAAA))
		assert.NotNil(t, rw.Msg)
		assert.Nil(t, rw.Msg.Answer)
	})
	t.Run("cache", func(t *testing.T) {
		conf := defaultConf
		conf.Cache.Size = 10
		h, err := newHandle(conf)
		assert.Nil(t, err)
		assert.NotNil(t, h)

		req := buildReq("a.cn", dns.TypeA)
		h.cache.Set(req, &dns.Msg{
			Answer: []dns.RR{&dns.A{}, &dns.AAAA{}},
		})
		rw := utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("a.cn", dns.TypeA))
		assert.NotNil(t, rw.Msg)
		assert.Equal(t, 2, len(rw.Msg.Answer))
	})
	t.Run("group", func(t *testing.T) {
		conf := defaultConf
		conf.Groups["a"] = config.Group{
			Rules: []string{"a.cn"},
		}
		h, err := newHandle(conf)
		assert.Nil(t, err)
		assert.NotNil(t, h)

		var srcGroup outbound.IGroup
		h.redirector = func(src outbound.IGroup, req, resp *dns.Msg) outbound.IGroup {
			srcGroup = src
			return src
		}

		rw := utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("a.cn", dns.TypeA))
		assert.NotNil(t, srcGroup)
		assert.Equal(t, "a", srcGroup.Name())
	})
}
