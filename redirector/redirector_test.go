package redirector

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/outbound"
	"testing"
)

func newResp(ip string) *dns.Msg {
	resp := new(dns.Msg)
	rr, err := dns.NewRR("z.cn. 0 IN A " + ip)
	if err != nil {
		panic(err)
	}
	resp.Answer = append(resp.Answer, rr)
	return resp
}

func Test_newCidrRedirector(t *testing.T) {
	t.Run("unknown_dst", func(t *testing.T) {
		conf := config.RedirectorConf{
			Type:      TypeMatchCidr,
			Rules:     []string{"1.1.1.0/24"},
			RulesFile: "",
			DstGroup:  "group1",
		}
		_, err := newCidrRedirector("redir1", conf, nil)
		assert.NotNil(t, err)
		t.Log(err)
	})
	t.Run("strange_file", func(t *testing.T) {
		conf := config.RedirectorConf{
			Type:      TypeMatchCidr,
			Rules:     []string{"1.1.1.0/24"},
			RulesFile: "testdata/not_exists.txt",
			DstGroup:  "group1",
		}
		groups := map[string]outbound.IGroup{"group1": outbound.MockGroup{}}
		_, err := newCidrRedirector("redir1", conf, groups)
		assert.NotNil(t, err)
		t.Log(err)

		conf.RulesFile = "testdata/strange_cidr.txt"
		_, err = newCidrRedirector("redir1", conf, groups)
		assert.NotNil(t, err)
		t.Log(err)
	})
	t.Run("match", func(t *testing.T) {
		conf := config.RedirectorConf{
			Type:      TypeMatchCidr,
			Rules:     []string{"1.1.1.0/24"},
			RulesFile: "testdata/normal_cidr.txt",
			DstGroup:  "group1",
		}
		groups := map[string]outbound.IGroup{"group1": outbound.MockGroup{}}
		redir, err := newCidrRedirector("redir1", conf, groups)
		t.Logf("%s", redir)
		assert.Nil(t, err)

		assert.NotNil(t, redir.Redirect(nil, newResp("1.1.1.1")))
		assert.NotNil(t, redir.Redirect(nil, newResp("1.1.2.1")))
		assert.Nil(t, redir.Redirect(nil, newResp("1.1.3.1")))
	})
	t.Run("mismatch", func(t *testing.T) {
		conf := config.RedirectorConf{
			Type:      TypeMisMatchCidr,
			Rules:     []string{"1.1.1.0/24"},
			RulesFile: "testdata/normal_cidr.txt",
			DstGroup:  "group1",
		}
		groups := map[string]outbound.IGroup{"group1": outbound.MockGroup{}}
		redir, err := newCidrRedirector("redir1", conf, groups)
		assert.Nil(t, err)

		assert.Nil(t, redir.Redirect(nil, newResp("1.1.1.1")))
		assert.Nil(t, redir.Redirect(nil, newResp("1.1.2.1")))
		assert.NotNil(t, redir.Redirect(nil, newResp("1.1.3.1")))
	})
}

func TestNewRedirector(t *testing.T) {
	//src := outbound.MockGroup{}
	t.Run("unknown_type", func(t *testing.T) {
		conf := config.Conf{
			Redirectors: map[string]config.RedirectorConf{
				"redir1": {Type: ""},
			},
		}
		group1 := outbound.MockGroup{}
		groups := map[string]outbound.IGroup{"group1": group1}
		_, err := NewRedirector(conf, groups)
		assert.NotNil(t, err)
		t.Logf("%s", err)
	})
	t.Run("unknown_redir", func(t *testing.T) {
		conf := config.Conf{
			Groups: map[string]config.Group{
				"g1": {Redirector: "redir1"},
			},
			Redirectors: map[string]config.RedirectorConf{
				"redir2": {Type: TypeMatchCidr, Rules: []string{"1.1.1.0/24"}, DstGroup: "g1"},
			},
		}
		groups := map[string]outbound.IGroup{"g1": outbound.MockGroup{}}
		_, err := NewRedirector(conf, groups)
		assert.NotNil(t, err)
		t.Logf("%s", err)
	})
	t.Run("redirect_cycle", func(t *testing.T) {
		conf := config.Conf{
			Groups: map[string]config.Group{
				"g1": {Redirector: "redir1"},
			},
			Redirectors: map[string]config.RedirectorConf{
				"redir1": {Type: TypeMatchCidr, Rules: []string{"1.1.1.0/24"}, DstGroup: "g1"},
			},
		}
		g1 := outbound.MockGroup{
			MockName:   func() string { return "g1" },
			MockString: func() string { return "group_g1" },
		}
		groups := map[string]outbound.IGroup{"g1": g1}
		redir, err := NewRedirector(conf, groups)
		assert.Nil(t, err)
		newGroup := redir(g1, nil, newResp("1.1.1.1"))
		assert.Nil(t, newGroup)
	})
	t.Run("redirect_success", func(t *testing.T) {
		conf := config.Conf{
			Groups: map[string]config.Group{
				"g1": {Redirector: "redir1"},
			},
			Redirectors: map[string]config.RedirectorConf{
				"redir1": {Type: TypeMatchCidr, Rules: []string{"1.1.1.0/24"}, DstGroup: "g2"},
			},
		}
		g1 := outbound.MockGroup{
			MockName:   func() string { return "g1" },
			MockString: func() string { return "group_g1" },
		}
		g2 := outbound.MockGroup{
			MockName:   func() string { return "g2" },
			MockString: func() string { return "group_g2" },
		}
		groups := map[string]outbound.IGroup{"g1": g1, "g2": g2}
		redir, err := NewRedirector(conf, groups)
		assert.Nil(t, err)
		assert.NotNil(t, redir)
		newGroup := redir(g1, nil, newResp("1.1.1.1"))
		assert.NotNil(t, newGroup)
		assert.Equal(t, "g2", newGroup.Name())
	})
	t.Run("redirect_empty", func(t *testing.T) {
		conf := config.Conf{
			Groups: map[string]config.Group{
				"g1": {},
			},
			Redirectors: map[string]config.RedirectorConf{
				"redir1": {Type: TypeMatchCidr, Rules: []string{"1.1.1.0/24"}, DstGroup: "g1"},
			},
		}
		g1 := outbound.MockGroup{
			MockName:   func() string { return "g1" },
			MockString: func() string { return "group_g1" },
		}
		g2 := outbound.MockGroup{
			MockName:   func() string { return "g2" },
			MockString: func() string { return "group_g2" },
		}
		groups := map[string]outbound.IGroup{"g1": g1, "g2": g2}
		redir, err := NewRedirector(conf, groups)
		assert.Nil(t, err)
		assert.NotNil(t, redir)
		newGroup := redir(g1, nil, newResp("1.1.1.1"))
		assert.Nil(t, newGroup)
	})
}
