package outbound

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
)

func TestBuildGroups(t *testing.T) {
	gfwListFile := "../matcher/testdata/gfwlist.txt"
	t.Run("fallback", func(t *testing.T) {
		_, err := BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {},
		}})
		assert.Nil(t, err)
		t.Log(err)

		_, err = BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {},
		}})
		assert.Nil(t, err)

		_, err = BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {},
			"g2": {},
		}})
		assert.NotNil(t, err)
		t.Log(err)
	})
	t.Run("gfw", func(t *testing.T) {
		_, err := BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {GFWListFile: "not_exists.txt"},
		}})
		assert.NotNil(t, err)

		_, err = BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {GFWListFile: gfwListFile},
		}})
		assert.Nil(t, err)

		_, err = BuildGroups(config.Conf{Groups: map[string]config.Group{
			"g1": {GFWListFile: gfwListFile},
			"g2": {GFWListFile: gfwListFile},
		}})
		assert.NotNil(t, err)
		t.Log(err)
	})
}

func TestDisableIPv6(t *testing.T) {
	groups, err := BuildGroups(config.Conf{Groups: map[string]config.Group{
		"g1": {DisableIPv6: true, DisableQTypes: []string{"AAAA"}},
	}})
	assert.Nil(t, err)
	g := groups["g1"]
	assert.NotNil(t, g)
	resp := g.Handle(&dns.Msg{
		Question: []dns.Question{{
			Name:   "z.cn.",
			Qtype:  dns.TypeAAAA,
			Qclass: 0,
		}},
	})
	assert.Nil(t, resp)
}
