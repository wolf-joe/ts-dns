package outbound

import (
	"fmt"
	mock "github.com/agiledragon/gomonkey"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	mock2 "github.com/wolf-joe/ts-dns/mock"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"
)

var dialer, _ = proxy.SOCKS5("tcp", "", nil, proxy.Direct)

func assertFail(t *testing.T, val *dns.Msg, err error) {
	assert.Nil(t, val)
	assert.NotNil(t, err)
}
func assertSuccess(t *testing.T, val *dns.Msg, err error) {
	assert.NotNil(t, val)
	assert.Nil(t, err)
}

func MockMethodSeq(target interface{}, methodName string, outputs []mock.Params) *mock.Patches {
	var cells []mock.OutputCell
	for _, output := range outputs {
		cells = append(cells, mock.OutputCell{Values: output})
	}
	return mock.ApplyMethodSeq(reflect.TypeOf(target), methodName, cells)
}

func TestDNSCaller(t *testing.T) {
	req := &dns.Msg{}

	caller := NewDNSCaller("", "", nil)
	// 不使用代理，mock掉Exchange
	p := MockMethodSeq(caller.client, "Exchange", []mock.Params{
		{nil, time.Second, fmt.Errorf("err")},
		{&dns.Msg{}, time.Second, nil},
	})
	// exchange调用失败
	r, err := caller.Call(req)
	assertFail(t, r, err)
	// exchange调用成功
	r, err = caller.Call(req)
	assertSuccess(t, r, err)

	caller = NewDoTCaller("", "", dialer)
	// 使用代理，mock掉Dial、WriteMsg、ReadMsg
	p1 := MockMethodSeq(caller.proxy, "Dial", []mock.Params{
		{nil, fmt.Errorf("err")},
		{&net.TCPConn{}, nil}, {&net.TCPConn{}, nil}, {&net.TCPConn{}, nil},
	})
	p2 := MockMethodSeq(caller.conn, "WriteMsg", []mock.Params{
		{fmt.Errorf("err")}, {nil}, {nil},
	})
	p3 := MockMethodSeq(caller.conn, "ReadMsg", []mock.Params{
		{nil, fmt.Errorf("err")}, {&dns.Msg{}, nil},
	})
	defer func() { p.Reset(); p1.Reset(); p2.Reset(); p3.Reset() }()
	// Dial失败
	r, err = caller.Call(req)
	assertFail(t, r, err)
	// Dial成功，但WriteMsg失败
	r, err = caller.Call(req)
	assertFail(t, r, err)
	// Dial、WriteMsg成功，但ReadMsg失败
	r, err = caller.Call(req)
	assertFail(t, r, err)
	// Dial、WriteMsg、ReadMsg都成功
	r, err = caller.Call(req)
	assertSuccess(t, r, err)
}

func TestDoHCaller(t *testing.T) {
	mocker := mock2.NewMocker()
	defer mocker.Reset()

	req := &dns.Msg{}
	caller := NewDoHCaller("", "", dialer)
	httpReq := &http.Request{Header: map[string][]string{}}

	mocker.MethodSeq(req, "PackBuffer", []mock.Params{
		{nil, fmt.Errorf("err")}, {[]byte{1}, nil}, {[]byte{1}, nil},
		{[]byte{1}, nil}, {[]byte{1}, nil}, {[]byte{1}, nil},
	})
	mocker.FuncSeq(http.NewRequest, []mock.Params{
		{nil, fmt.Errorf("err")}, {httpReq, nil}, {httpReq, nil},
		{httpReq, nil}, {httpReq, nil},
	})
	mocker.MethodSeq(caller.client, "Do", []mock.Params{
		{nil, fmt.Errorf("err")}, {&http.Response{Body: &net.TCPConn{}}, nil},
		{&http.Response{Body: &net.TCPConn{}}, nil},
		{&http.Response{Body: &net.TCPConn{}}, nil},
	})
	mocker.FuncSeq(ioutil.ReadAll, []mock.Params{
		{nil, fmt.Errorf("err")}, {make([]byte, 1), nil},
		{make([]byte, 12), nil},
	})

	// Pack失败
	r, err := caller.Call(req)
	assertFail(t, r, err)
	// Pack成功，但NewRequest失败
	r, err = caller.Call(req)
	assertFail(t, r, err)
	// Pack、NewRequest成功，但Do失败
	r, err = caller.Call(req)
	assertFail(t, r, err)
	// Pack、NewRequest、Do成功，但ReadAll失败
	r, err = caller.Call(req)
	assertFail(t, r, err)
	// Pack、NewRequest、Do、ReadAll成功，但Unpack失败
	r, err = caller.Call(req)
	assertFail(t, r, err)
	// Pack、NewRequest、Do、ReadAll、Unpack成功
	r, err = caller.Call(req)
	assertSuccess(t, r, err)
}
