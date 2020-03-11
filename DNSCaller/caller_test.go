package DNSCaller

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/proxy"
	"os"
	"testing"
)

var question = dns.Question{Name: "ip.cn.", Qtype: dns.TypeA}
var fakeQuest = dns.Question{Name: "ip.cn", Qtype: dns.TypeA}
var s5dialer, _ = proxy.SOCKS5("tcp", os.Getenv("SOCKS5"), nil, proxy.Direct)
var fakeDialer, _ = proxy.SOCKS5("tcp", os.Getenv("SOCKS5")+"ne", nil, proxy.Direct)

func assertFail(t *testing.T, val *dns.Msg, err error) {
	assert.NotEqual(t, err, nil)
	assert.True(t, val == nil)
}
func assertSuccess(t *testing.T, val interface{}, err error) {
	assert.Equal(t, err, nil)
	assert.True(t, val != nil)
}

func TestUDPCaller(t *testing.T) {
	address := "8.8.8.8:53"
	caller := UDPCaller{address: address + "ne"}
	r, err := caller.Call(question, []dns.RR{}, nil)
	assertFail(t, r, err)

	caller = UDPCaller{address: address}
	r, err = caller.Call(question, []dns.RR{}, nil)
	assertSuccess(t, r, err)
	r, err = caller.Call(question, []dns.RR{}, s5dialer)
	assertSuccess(t, r, err)
	r, err = caller.Call(fakeQuest, []dns.RR{}, s5dialer)
	assertFail(t, r, err)
	r, err = caller.Call(question, []dns.RR{}, fakeDialer)
	assertFail(t, r, err)
}
