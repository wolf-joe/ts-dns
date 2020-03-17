package inbound

import (
	"fmt"
	"github.com/agiledragon/gomonkey"
	"github.com/janeczku/go-ipset/ipset"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/mock"
	"github.com/wolf-joe/ts-dns/outbound"
	"net"
	"sync"
	"testing"
)

type MockResp struct {
	dns.ResponseWriter
	r *dns.Msg
}

func (r *MockResp) WriteMsg(resp *dns.Msg) error {
	r.r = resp
	return nil
}

func (r *MockResp) Close() error {
	return nil
}

func (r *MockResp) RemoteAddr() net.Addr {
	return &net.IPNet{}
}

func TestHandler(t *testing.T) {
	// 初始化handler
	handler := &Handler{Mux: new(sync.RWMutex), Cache: cache.NewDNSCache(0, 0, 0),
		GFWMatcher: matcher.NewABPByText(""), CNIP: cache.NewRamSetByText(""),
		HostsReaders: []hosts.Reader{hosts.NewReaderByText("")},
	}
	callers := []outbound.Caller{&outbound.DNSCaller{}}
	group := &Group{Callers: callers, Matcher: matcher.NewABPByText(""), IPSet: &ipset.IPSet{}}
	handler.GroupMap = map[string]*Group{"clean": group, "dirty": group}
	// 初始化所需参数和返回值
	resp := &dns.Msg{Answer: []dns.RR{&dns.A{A: net.ParseIP("1.1.1.1")}}}
	writer, req := &MockResp{}, &dns.Msg{}
	req.SetQuestion("ip.cn.", dns.TypeA)

	mocker := mock.NewMocker()
	// mock掉hosts
	mocker.MethodSeq(handler.HostsReaders[0], "Record", []gomonkey.Params{
		{"ip.cn 0 IN A ???"}, {"ip.cn. 0 IN A 1.1.1.1"},
	})
	handler.ServeDNS(writer, req) // 命中hosts且NewRR失败
	assert.Nil(t, writer.r)
	handler.ServeDNS(writer, req) // 命中hosts且NewRR成功
	assert.NotNil(t, writer.r)
	mocker.Reset()
	// mock掉cache
	mocker.MethodSeq(handler.Cache, "Get", []gomonkey.Params{{resp}})
	handler.ServeDNS(writer, req) // 命中cache
	assert.NotNil(t, writer.r)
	mocker.Reset()
	// mock掉group的matcher、callDNS、addIPSet
	mocker.MethodSeq(group.Matcher, "Match", []gomonkey.Params{{true, true}})
	mocker.FuncSeq(callDNS, []gomonkey.Params{{resp}})
	mocker.FuncSeq(addIPSet, []gomonkey.Params{{nil}})
	handler.ServeDNS(writer, req) // 命中rules，调用callDNS后addIPSet
	assert.NotNil(t, writer.r)
	mocker.Reset()
	// mock掉callDNS和extractIPv4、CN IP、addIPSet
	mocker.FuncSeq(callDNS, []gomonkey.Params{
		{resp}, {resp}, {resp}, {resp},
	})
	mocker.FuncSeq(extractIPv4, []gomonkey.Params{
		{[]string{"1.1.1.1"}}, {[]string{"1.1.1.1"}}, {[]string{"1.1.1.1"}},
	})
	mocker.MethodSeq(handler.CNIP, "Contain", []gomonkey.Params{
		{true}, {false}, {false},
	})
	mocker.FuncSeq(addIPSet, []gomonkey.Params{
		{fmt.Errorf("err")}, {nil}, {nil},
	})
	handler.ServeDNS(writer, req) // 都是cn ip
	assert.NotNil(t, writer.r)
	// mock掉matcher，包括两个rule matcher和gfw matcher，一次ServerDNS需要三个返回值
	mocker.MethodSeq(group.Matcher, "Match", []gomonkey.Params{
		{false, true}, {false, true}, {false, true},
		{false, true}, {false, true}, {true, true},
	})
	handler.ServeDNS(writer, req) // 存在非cn ip，且被gfw匹配
	assert.NotNil(t, writer.r)
	handler.ServeDNS(writer, req) // 存在非cn ip，且未被gfw匹配
	assert.NotNil(t, writer.r)

	mocker.Reset()
	handler.Refresh(handler)
}
