package hosts

import (
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
	"testing"
)

func buildReq(host string, qType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.Question = append(msg.Question, dns.Question{
		Name:   host,
		Qtype:  qType,
		Qclass: 0,
	})
	return msg
}

func TestNewHostReader(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	cfg := config.Conf{Hosts: map[string]string{
		"z.cn": "1.1.1.1",
	}, HostsFiles: []string{
		"testdata/test.txt",
	}}
	r, err := NewDNSHosts(cfg)
	assert.Nil(t, err)
	assert.NotNil(t, r)

	resp := r.Get(buildReq("z.cn.", dns.TypeA))
	assert.NotNil(t, resp)
	assert.Equal(t, "z.cn.\t0\tIN\tA\t1.1.1.1", resp.Answer[0].String())

	cases := []struct {
		host  string
		query uint16
		isNil bool
	}{
		{"z.cn", dns.TypeA, false},
		{"z.cn", dns.TypeAAAA, true},
		{"comment1.com", dns.TypeA, true},
		{"comment2.com", dns.TypeA, true},
		{"space_suffix.com", dns.TypeA, false},
		{"hello.wildcard1.com", dns.TypeA, false},
		{"a.wildcard2.com", dns.TypeA, false},
		{"v6.com", dns.TypeA, true},
		{"v6.com", dns.TypeAAAA, false},
	}
	for _, c := range cases {
		t.Log(c)
		resp = r.Get(buildReq(c.host, c.query))
		assert.Nil(t, err)
		if c.isNil {
			assert.Nil(t, resp)
		} else {
			assert.NotNil(t, resp)
		}
	}

	cfg = config.Conf{HostsFiles: []string{
		"testdata/invalid.txt",
	}}
	_, err = NewDNSHosts(cfg)
	t.Logf("%+v", err)
	assert.NotNil(t, err)

	cfg = config.Conf{HostsFiles: []string{
		"testdata/not_exists.txt",
	}}
	_, err = NewDNSHosts(cfg)
	t.Logf("%+v", err)
	assert.NotNil(t, err)
}

func BenchmarkHostReader_Regexp(b *testing.B) {
	hosts, err := NewDNSHosts(config.Conf{Hosts: map[string]string{
		"z.cn":    "1.1.1.1",
		"*.wd.cn": "1.1.1.1",
	}})
	assert.Nil(b, err)
	req := buildReq("test.wd.cn", dns.TypeA)
	for i := 0; i < b.N; i++ {
		resp := hosts.Get(req)
		assert.NotNil(b, resp)
	}
}

func BenchmarkHostReader_Domain(b *testing.B) {
	r, err := NewDNSHosts(config.Conf{Hosts: map[string]string{
		"z.cn":    "1.1.1.1",
		"*.wd.cn": "1.1.1.1",
	}})
	assert.Nil(b, err)
	req := buildReq("z.cn", dns.TypeA)
	for i := 0; i < b.N; i++ {
		resp := r.Get(req)
		assert.NotNil(b, resp)
	}
}
