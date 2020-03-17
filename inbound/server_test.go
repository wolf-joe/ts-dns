package inbound

import (
	"fmt"
	mock "github.com/agiledragon/gomonkey"
	"github.com/janeczku/go-ipset/ipset"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/outbound"
	"net"
	"reflect"
	"sync"
	"testing"
)

type MockResp struct{ dns.ResponseWriter }

func (r *MockResp) WriteMsg(_ *dns.Msg) error {
	return nil
}

func (r *MockResp) Close() error {
	return nil
}

func (r *MockResp) RemoteAddr() net.Addr {
	return &net.IPNet{}
}

func MockFuncSeq(target interface{}, outputs []mock.Params) *mock.Patches {
	var cells []mock.OutputCell
	for _, output := range outputs {
		cells = append(cells, mock.OutputCell{Values: output})
	}
	return mock.ApplyFuncSeq(target, cells)
}

func MockMethodSeq(target interface{}, methodName string, outputs []mock.Params) *mock.Patches {
	var cells []mock.OutputCell
	for _, output := range outputs {
		cells = append(cells, mock.OutputCell{Values: output})
	}
	return mock.ApplyMethodSeq(reflect.TypeOf(target), methodName, cells)
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

	// mock掉hosts
	p := MockMethodSeq(handler.HostsReaders[0], "Record", []mock.Params{
		{"error"}, {"ip.cn. 0 IN A 1.1.1.1"},
	})
	handler.ServeDNS(writer, req) // 命中hosts且NewRR失败
	handler.ServeDNS(writer, req) // 命中hosts且NewRR成功
	p.Reset()
	// mock掉cache
	p = MockMethodSeq(handler.Cache, "Get", []mock.Params{{resp}})
	handler.ServeDNS(writer, req) // 命中cache
	p.Reset()
	// mock掉group的matcher、callDNS、addIPSet
	p = MockMethodSeq(group.Matcher, "Match", []mock.Params{{true, true}})
	pCall := MockFuncSeq(callDNS, []mock.Params{{resp}})
	pAdd := MockFuncSeq(addIPSet, []mock.Params{{nil}})
	handler.ServeDNS(writer, req) // 命中rules，调用callDNS后addIPSet
	p.Reset()
	pCall.Reset()
	pAdd.Reset()
	// mock掉callDNS和extractIPv4、CN IP、addIPSet
	var patches []*mock.Patches
	patches = append(patches, MockFuncSeq(callDNS, []mock.Params{
		{resp}, {resp}, {resp}, {resp},
	}))
	patches = append(patches, MockFuncSeq(extractIPv4, []mock.Params{
		{[]string{"1.1.1.1"}}, {[]string{"1.1.1.1"}}, {[]string{"1.1.1.1"}},
	}))
	patches = append(patches, MockMethodSeq(handler.CNIP, "Contain",
		[]mock.Params{{true}, {false}, {false}}))
	patches = append(patches, MockFuncSeq(addIPSet, []mock.Params{
		{fmt.Errorf("err")}, {nil}, {nil},
	}))
	handler.ServeDNS(writer, req) // 都是cn ip
	// mock掉matcher，包括两个rule matcher和gfw matcher，一次ServerDNS需要三个返回值
	patches = append(patches, MockMethodSeq(group.Matcher, "Match", []mock.Params{
		{false, true}, {false, true}, {false, true},
		{false, true}, {false, true}, {true, true},
	}))
	handler.ServeDNS(writer, req) // 存在非cn ip，且被gfw匹配
	handler.ServeDNS(writer, req) // 存在非cn ip，且未被gfw匹配

	for _, p := range patches {
		p.Reset()
	}

	handler.Refresh(handler)
}
