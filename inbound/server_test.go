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

type MockRespWriter struct {
	dns.ResponseWriter
	r *dns.Msg
}

func (r *MockRespWriter) WriteMsg(resp *dns.Msg) error {
	r.r = resp
	return nil
}

func (r *MockRespWriter) Close() error {
	return nil
}

func (r *MockRespWriter) RemoteAddr() net.Addr {
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
	handler.Groups = map[string]*Group{"clean": group, "dirty": group}
	// 初始化所需参数和返回值
	resp := &dns.Msg{Answer: []dns.RR{&dns.A{A: net.ParseIP("1.1.1.1")}}}
	writer, req := &MockRespWriter{}, &dns.Msg{}
	req.SetQuestion("ip.cn.", dns.TypeA)

	mocker := mock.NewMocker()
	defer mocker.Reset()

	// 测试HitHosts
	mocker.MethodSeq(handler.HostsReaders[0], "Record", []gomonkey.Params{
		{""}, {""}, {"ip.cn 0 IN A ???"}, {"ip.cn 0 IN A 1.1.1.1"},
	})
	assert.Nil(t, handler.HitHosts(req))    // Record返回空串（需要两个返回值）
	assert.Nil(t, handler.HitHosts(req))    // Record返回值格式不正确
	assert.NotNil(t, handler.HitHosts(req)) // Record返回值正常

	// 测试ServeDNS前半部分
	// mock HitHosts
	mocker.MethodSeq(handler, "HitHosts", []gomonkey.Params{
		{resp}, {nil}, {nil}, // 前半部分用
		{nil}, {nil}, {nil},
	})
	handler.ServeDNS(writer, req) // 命中hosts
	assert.Equal(t, writer.r, resp)
	// mock缓存
	mocker.MethodSeq(handler.Cache, "Get", []gomonkey.Params{
		{resp}, {nil}, // 前半部分用
		{nil}, {resp}, {nil}, {resp}, {nil}, {resp},
	})
	handler.ServeDNS(writer, req) // 命中缓存
	assert.Equal(t, writer.r, resp)
	// mock 规则匹配结果
	mocker.MethodSeq(group.Matcher, "Match", []gomonkey.Params{
		{true, true}, // 前半部分用，只包含一次匹配
		// 后半部分需要两个不匹配跳过规则（可能要再加上GFWList的匹配/不匹配）
		{false, false}, {false, false},
		{false, false}, {false, false}, {false, false},
		{false, false}, {false, false}, {true, true},
	})
	// 规则匹配后mock CallDNS
	mocker.MethodSeq(group, "CallDNS", []gomonkey.Params{
		{resp}, // 前半部分用
		{resp}, {resp}, {resp}, {resp},
	})
	handler.ServeDNS(writer, req) // 命中规则
	assert.Equal(t, writer.r, resp)

	// 测试ServeDNS后半部分：CN IP+GFWList
	// mock allInRange
	mocker.FuncSeq(allInRange, []gomonkey.Params{
		{true}, {false}, {false},
	})
	handler.ServeDNS(writer, req) // 未出现非cn ip，直接返回
	assert.Equal(t, writer.r, resp)
	handler.ServeDNS(writer, req) // 出现非cn ip但不匹配GFWList，直接返回
	assert.Equal(t, writer.r, resp)
	handler.ServeDNS(writer, req) // 出现非cn ip且匹配GFWList，调dirty组CallDNS并返回
	assert.Equal(t, writer.r, resp)

	// 测试Refresh
	handler.Refresh(handler)
}

func TestGroup(t *testing.T) {
	callers := []outbound.Caller{&outbound.DNSCaller{}}
	group := &Group{Callers: callers, Matcher: matcher.NewABPByText(""), IPSet: &ipset.IPSet{}}

	mocker := mock.NewMocker()
	defer mocker.Reset()

	resp := &dns.Msg{Answer: []dns.RR{&dns.A{A: net.IPv4(1, 1, 1, 1)}}}
	// 测试CallDNS
	assert.Nil(t, group.CallDNS(nil))
	mocker.MethodSeq(callers[0], "Call", []gomonkey.Params{
		{nil, fmt.Errorf("err")}, {resp, nil},
		{nil, fmt.Errorf("err")}, {resp, nil},
	})
	assert.Nil(t, group.CallDNS(&dns.Msg{}))    // Call返回error
	assert.NotNil(t, group.CallDNS(&dns.Msg{})) // Call正常返回
	// 测试并发CallDNS。两个Caller的并发在单测（-race）时会和mock冲突，这里就不测了
	//group.Callers = append(group.Callers, &outbound.DNSCaller{})
	group.Concurrent = true
	assert.Nil(t, group.CallDNS(&dns.Msg{}))
	assert.NotNil(t, group.CallDNS(&dns.Msg{}))
	// 测试AddIPSet
	group.AddIPSet(nil)
	mocker.MethodSeq(group.IPSet, "Add", []gomonkey.Params{
		{fmt.Errorf("err")}, {nil},
	})
	group.AddIPSet(resp) // Add返回error
	group.AddIPSet(resp) // Add正常返回
}
