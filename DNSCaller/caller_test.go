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
func assertSuccess(t *testing.T, val *dns.Msg, err error) {
	assert.Equal(t, err, nil)
	assert.True(t, len(val.Answer) > 0)
}

func TestUDPCaller(t *testing.T) {
	request, fakeRequest := &dns.Msg{}, &dns.Msg{}
	request.SetQuestion(question.Name, question.Qtype)
	fakeRequest.SetQuestion(fakeQuest.Name, fakeQuest.Qtype)
	address := "1.1.1.1:53"
	caller := UDPCaller{Address: address + "ne"}
	r, err := caller.Call(request)
	assertFail(t, r, err)

	caller = UDPCaller{Address: address, Dialer: s5dialer}
	r, err = caller.Call(request)
	assertSuccess(t, r, err)
	r, err = caller.Call(fakeRequest)
	assertFail(t, r, err)
	caller = UDPCaller{Address: address, Dialer: fakeDialer}
	r, err = caller.Call(request)
	assertFail(t, r, err)
}

func TestTCPCaller(t *testing.T) {
	request, fakeRequest := &dns.Msg{}, &dns.Msg{}
	request.SetQuestion(question.Name, question.Qtype)
	fakeRequest.SetQuestion(fakeQuest.Name, fakeQuest.Qtype)
	address := "1.1.1.1:53"
	caller := TCPCaller{Address: address}
	r, err := caller.Call(request)
	assertSuccess(t, r, err)
	caller = TCPCaller{Address: address, Dialer: s5dialer}
	r, err = caller.Call(request)
	assertSuccess(t, r, err)
}

func TestTLSCaller(t *testing.T) {
	request, fakeRequest := &dns.Msg{}, &dns.Msg{}
	request.SetQuestion(question.Name, question.Qtype)
	fakeRequest.SetQuestion(fakeQuest.Name, fakeQuest.Qtype)
	address, serverName := "1.0.0.1:853", "cloudflare-dns.com"
	caller := NewTLSCaller(address, nil, serverName, false)
	r, err := caller.Call(request)
	assertSuccess(t, r, err)
	caller = NewTLSCaller(address, s5dialer, serverName, false)
	r, err = caller.Call(request)
	assertSuccess(t, r, err)
}

func TestDoHCaller(t *testing.T) {
	request, fakeRequest := &dns.Msg{}, &dns.Msg{}
	request.SetQuestion(question.Name, question.Qtype)
	fakeRequest.SetQuestion(fakeQuest.Name, fakeQuest.Qtype)
	url := "https://cloudflare-dns.com/dns-query"
	caller := DoHCaller{Url: "https://not-exists.com/dns-query"}
	r, err := caller.Call(request)
	assertFail(t, r, err)
	caller = DoHCaller{Url: url + "/ne"}
	r, err = caller.Call(request)
	assertFail(t, r, err)
	caller = DoHCaller{Url: url}
	r, err = caller.Call(request)
	assertSuccess(t, r, err)
	r, err = caller.Call(fakeRequest)
	assertFail(t, r, err)
	caller = DoHCaller{Url: url, Dialer: s5dialer}
	r, err = caller.Call(request)
	assertSuccess(t, r, err)
}
