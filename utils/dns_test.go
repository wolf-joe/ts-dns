package utils

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseECS(t *testing.T) {
	ecs, err := ParseECS("")
	assert.Nil(t, ecs)
	assert.Nil(t, err)
	ecs, err = ParseECS("??????")
	assert.Nil(t, ecs)
	assert.NotNil(t, err)
	ecs, err = ParseECS("1.1.1.1/33")
	assert.Nil(t, ecs)
	assert.NotNil(t, err)
	ecs, err = ParseECS("1.1.1.256")
	assert.Nil(t, ecs)
	assert.NotNil(t, err)
	ecs, err = ParseECS("1.1.1.1/24")
	assert.NotNil(t, ecs)
	assert.Nil(t, err)
	ecs, err = ParseECS("1.1.1.1")
	assert.NotNil(t, ecs)
	assert.Nil(t, err)
	ecs, err = ParseECS("::1/128")
	assert.NotNil(t, ecs)
	assert.Nil(t, err)
	ecs, err = ParseECS("::1")
	assert.NotNil(t, ecs)
	assert.Nil(t, err)
}

func TestFormatECS(t *testing.T) {
	assert.Empty(t, FormatECS(nil))
	r := &dns.Msg{}
	r.Extra = append(r.Extra, &dns.OPT{Option: []dns.EDNS0{&dns.EDNS0_COOKIE{}}})
	assert.Empty(t, FormatECS(r))
	r.Extra[0].(*dns.OPT).Option[0], _ = ParseECS("1.1.1.1")
	assert.Equal(t, FormatECS(r), "1.1.1.1/32")
	r.Extra[0].(*dns.OPT).Option[0], _ = ParseECS("1.1.1.1/24")
	assert.Equal(t, FormatECS(r), "1.1.1.1/24")
}

func TestSetDefaultECS(t *testing.T) {
	r := &dns.Msg{}
	SetDefaultECS(r, nil)
	assert.Equal(t, FormatECS(r), "")
	ecs, _ := ParseECS("1.1.1.1")
	SetDefaultECS(r, ecs)
	assert.Equal(t, FormatECS(r), "1.1.1.1/32")
	r = &dns.Msg{Extra: []dns.RR{&dns.OPT{Option: []dns.EDNS0{&dns.EDNS0_COOKIE{}}}}}
	SetDefaultECS(r, ecs)
	assert.Equal(t, len(r.Extra), 1)
	assert.Equal(t, len(r.Extra[0].(*dns.OPT).Option), 2)
	assert.Equal(t, FormatECS(r), "1.1.1.1/32")
	// 已有ecs信息时SetDefaultECS不执行动作
	ecs, _ = ParseECS("2.2.2.2")
	SetDefaultECS(r, ecs)
	assert.Equal(t, len(r.Extra), 1)
	assert.Equal(t, len(r.Extra[0].(*dns.OPT).Option), 2)
	assert.Equal(t, FormatECS(r), "1.1.1.1/32")
}

func TestRemoveEDNSCookie(t *testing.T) {
	RemoveEDNSCookie(nil)
	msg := &dns.Msg{}
	ecs, _ := ParseECS("1.1.1.1")
	SetDefaultECS(msg, ecs)
	opt := msg.Extra[0].(*dns.OPT)
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "abc"})
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "def"})
	assert.Equal(t, 3, len(opt.Option))
	RemoveEDNSCookie(msg)
	assert.Equal(t, 1, len(opt.Option))
	RemoveEDNSCookie(msg)
	assert.Equal(t, 1, len(opt.Option))
}

func TestRemoveA(t *testing.T) {
	RemoveA(nil)
	resp := &dns.Msg{}
	RemoveA(resp)
	assert.Equal(t, 0, len(resp.Answer))

	resp.Answer = append(resp.Answer, &dns.CNAME{})
	assert.Equal(t, 1, len(resp.Answer))
	RemoveA(resp)
	assert.Equal(t, 1, len(resp.Answer))

	resp.Answer = append(resp.Answer, &dns.A{})
	resp.Answer = append(resp.Answer, &dns.A{})
	assert.Equal(t, 3, len(resp.Answer))
	RemoveA(resp)
	assert.Equal(t, 1, len(resp.Answer))
}
