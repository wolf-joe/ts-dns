package inbound

import (
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
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
	t.Run("disable", func(t *testing.T) {
		_, err := newHandle(config.Conf{
			HostsFiles:    nil,
			Hosts:         nil,
			Cache:         config.CacheConf{},
			Groups:        nil,
			DisableIPv6:   true,
			DisableQTypes: []string{"??"},
			Redirectors:   nil,
			Listen:        "",
		})
		assert.NotNil(t, err)
		t.Log(err)

		h, err := newHandle(config.Conf{
			HostsFiles:    nil,
			Hosts:         nil,
			Cache:         config.CacheConf{},
			Groups:        map[string]config.Group{"default": {}},
			DisableIPv6:   true,
			DisableQTypes: []string{"NS"},
			Redirectors:   nil,
			Listen:        "",
		})
		assert.Nil(t, err)
		assert.NotNil(t, h)
		rw := utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("z.cn", dns.TypeAAAA))
		assert.NotNil(t, rw.Msg)
		assert.Nil(t, rw.Msg.Answer)

		rw = utils.NewFakeRespWriter()
		h.ServeDNS(rw, buildReq("z.cn", dns.TypeNS))
		assert.NotNil(t, rw.Msg)
		assert.Nil(t, rw.Msg.Answer)
	})
}
