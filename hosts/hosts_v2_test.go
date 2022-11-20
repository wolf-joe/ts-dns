package hosts

import (
	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
	"testing"
)

func TestNewHostReader(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	cfg := &config.Conf{Hosts: map[string]string{
		"z.cn": "1.1.1.1",
	}, HostsFiles: []string{
		"testdata/test.txt",
	}}
	r, err := NewHostReader(cfg)
	assert.Nil(t, err)
	assert.NotNil(t, r)

	rr, err := r.Record("z.cn.", dns.TypeA)
	assert.Nil(t, err)
	assert.NotNil(t, rr)
	assert.Equal(t, "z.cn.\t0\tIN\tA\t1.1.1.1", rr.String())

	rr, err = r.Record("z.cn.", dns.TypeANY)
	t.Logf("%+v", err)
	assert.NotNil(t, err)

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
		rr, err = r.Record(c.host, c.query)
		assert.Nil(t, err)
		if c.isNil {
			assert.Nil(t, rr)
		} else {
			assert.NotNil(t, rr)
		}
	}

	cfg = &config.Conf{HostsFiles: []string{
		"testdata/invalid.txt",
	}}
	r, err = NewHostReader(cfg)
	t.Logf("%+v", err)
	assert.NotNil(t, err)

	cfg = &config.Conf{HostsFiles: []string{
		"testdata/not_exists.txt",
	}}
	r, err = NewHostReader(cfg)
	t.Logf("%+v", err)
	assert.NotNil(t, err)
}

func BenchmarkHostReader_Regexp(b *testing.B) {
	r, err := NewHostReader(&config.Conf{Hosts: map[string]string{
		"z.cn":    "1.1.1.1",
		"*.wd.cn": "1.1.1.1",
	}})
	assert.Nil(b, err)
	for i := 0; i < b.N; i++ {
		rr, err := r.Record("test.wd.cn", dns.TypeA)
		assert.NotNil(b, rr)
		assert.Nil(b, err)
	}
}

func BenchmarkHostReader_Domain(b *testing.B) {
	r, err := NewHostReader(&config.Conf{Hosts: map[string]string{
		"z.cn":    "1.1.1.1",
		"*.wd.cn": "1.1.1.1",
	}})
	assert.Nil(b, err)
	for i := 0; i < b.N; i++ {
		rr, err := r.Record("z.cn", dns.TypeA)
		assert.NotNil(b, rr)
		assert.Nil(b, err)
	}
}
