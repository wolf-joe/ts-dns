package common

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestExtractA(t *testing.T) {
	assert.Empty(t, ExtractA(nil))
	r := &dns.Msg{}
	assert.Empty(t, ExtractA(r))
	r.Answer = append(r.Answer, &dns.AAAA{})
	assert.Empty(t, ExtractA(r))
	r.Answer = append(r.Answer, &dns.A{})
	assert.Equal(t, len(ExtractA(r)), 1)
	r.Answer = append(r.Answer, &dns.TXT{})
	assert.Equal(t, len(ExtractA(r)), 1)
}

func TestParseSubnet(t *testing.T) {
	ecs, err := ParseSubnet("")
	assert.Nil(t, ecs)
	assert.Nil(t, err)
	ecs, err = ParseSubnet("??????")
	assert.Nil(t, ecs)
	assert.NotNil(t, err)
	ecs, err = ParseSubnet("1.1.1.1/33")
	assert.Nil(t, ecs)
	assert.NotNil(t, err)
	ecs, err = ParseSubnet("1.1.1.256")
	assert.Nil(t, ecs)
	assert.NotNil(t, err)
	ecs, err = ParseSubnet("1.1.1.1/24")
	assert.NotNil(t, ecs)
	assert.Nil(t, err)
	ecs, err = ParseSubnet("1.1.1.1")
	assert.NotNil(t, ecs)
	assert.Nil(t, err)
	ecs, err = ParseSubnet("::1/128")
	assert.NotNil(t, ecs)
	assert.Nil(t, err)
	ecs, err = ParseSubnet("::1")
	assert.NotNil(t, ecs)
	assert.Nil(t, err)
}

func TestFormatSubnet(t *testing.T) {
	assert.Empty(t, FormatSubnet(nil))
	r := &dns.Msg{}
	r.Extra = append(r.Extra, &dns.OPT{Option: []dns.EDNS0{&dns.EDNS0_COOKIE{}}})
	assert.Empty(t, FormatSubnet(r))
	r.Extra[0].(*dns.OPT).Option[0], _ = ParseSubnet("1.1.1.1")
	assert.Equal(t, FormatSubnet(r), "1.1.1.1/32")
	r.Extra[0].(*dns.OPT).Option[0], _ = ParseSubnet("1.1.1.1/24")
	assert.Equal(t, FormatSubnet(r), "1.1.1.1/24")
}
