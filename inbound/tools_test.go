package inbound

import (
	"fmt"
	mock "github.com/agiledragon/gomonkey"
	"github.com/janeczku/go-ipset/ipset"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/outbound"
	"net"
	"reflect"
	"testing"
)

func MockMethodSeq(target interface{}, methodName string, outputs []mock.Params) *mock.Patches {
	var cells []mock.OutputCell
	for _, output := range outputs {
		cells = append(cells, mock.OutputCell{Values: output})
	}
	return mock.ApplyMethodSeq(reflect.TypeOf(target), methodName, cells)
}

func TestTools(t *testing.T) {
	assert.Equal(t, len(extractIPv4(nil)), 0)
	resp := &dns.Msg{}
	assert.Equal(t, len(extractIPv4(resp)), 0)
	resp.Answer = append(resp.Answer, &dns.AAAA{AAAA: net.ParseIP("::1")})
	assert.Equal(t, len(extractIPv4(resp)), 0)
	resp.Answer = append(resp.Answer, &dns.A{A: net.ParseIP("127.0.0.1")})
	assert.Equal(t, len(extractIPv4(resp)), 1)

	assert.Nil(t, addIPSet(nil, resp), nil)
	group := &Group{}
	assert.Nil(t, addIPSet(group, resp), nil)
	group.IPSet = &ipset.IPSet{}
	assert.NotNil(t, addIPSet(group, resp), nil)

	req := &dns.Msg{}
	assert.Nil(t, callDNS(nil, nil), nil)
	assert.Nil(t, callDNS(group, req), nil)
	group.Callers = append(group.Callers, &outbound.DNSCaller{})
	// mock掉call的返回
	p := MockMethodSeq(group.Callers[0], "Call", []mock.Params{
		{nil, fmt.Errorf("err")}, {&dns.Msg{}, nil},
	})
	assert.Nil(t, callDNS(group, req), nil)
	assert.NotNil(t, callDNS(group, req), nil)
	p.Reset()
}
