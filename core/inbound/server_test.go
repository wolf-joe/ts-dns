package inbound

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fastrand"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/core/utils"
	"github.com/wolf-joe/ts-dns/core/utils/mock"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/outbound"
)

func mockListenAndServe(mocker *mock.Mocker, sleep time.Duration, err string) {
	target := &dns.Server{}
	mocker.Method(target, "ListenAndServe", func(s *dns.Server) error {
		time.Sleep(sleep)
		if err != "" {
			return fmt.Errorf("listen %s/%s error: %s", s.Addr, s.Net, err)
		}
		return nil
	})
}

func mockShutdownContext(mocker *mock.Mocker, err string) {
	target := &dns.Server{}
	mocker.Method(target, "ShutdownContext", func(s *dns.Server, ctx context.Context) error {
		if err != "" {
			return fmt.Errorf("shutdown %s/%s error: %s", s.Addr, s.Net, err)
		}
		return nil
	})
}

func TestDNSServer(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	mocker := new(mock.Mocker)
	defer mocker.Reset()

	ctx := utils.NewCtx(nil, 0xffff)
	server := NewDNSServer("127.0.0.1:5353", "", nil, nil, nil, nil)

	utils.CtxInfo(ctx, "---- test listen error ----")
	mockListenAndServe(mocker, 10*time.Millisecond, "unavailable now")
	server.Run(ctx)
	time.Sleep(20 * time.Millisecond)
	server.StopAndWait()

	utils.CtxInfo(ctx, "---- test immediate shutdown ----")
	mockListenAndServe(mocker, time.Hour, "")
	server.Run(ctx)
	server.StopAndWait()

	utils.CtxInfo(ctx, "---- test shutdown error ----")
	server = NewDNSServer("127.0.0.1:5353", "udp", nil, nil, nil, nil)
	mockShutdownContext(mocker, "system is busy")
	server.Run(ctx)
	time.Sleep(20 * time.Millisecond)
	server.StopAndWait()
}

// 初始化一个一次性caller。首次调用Call时返回指定数据，否则panic
func newOneTimeCaller(resp *dns.Msg) *oneTimeCaller {
	return &oneTimeCaller{resp: resp}
}

type oneTimeCaller struct {
	resp  *dns.Msg
	times int32
}

func (o *oneTimeCaller) Call(_ *dns.Msg) (*dns.Msg, error) {
	if atomic.AddInt32(&o.times, 1) == 1 {
		return o.resp, nil
	}
	panic("not first time")
}
func (o *oneTimeCaller) Exit()          {}
func (o *oneTimeCaller) String() string { return fmt.Sprintf("oneTimeCaller<%p>", o) }

func TestDNSServer_ServeDNS(t *testing.T) {
	// region init
	logrus.SetLevel(logrus.DebugLevel)
	mocker := new(mock.Mocker)
	defer mocker.Reset()
	writer := utils.NewFakeRespWriter()
	newReq := func(name string, qType uint16) *dns.Msg {
		msg := &dns.Msg{Question: []dns.Question{{
			Name: name, Qtype: qType,
		}}}
		msg.Id = uint16(fastrand.Uint32())
		return msg
	}
	newResp := func(rr []dns.RR) *dns.Msg {
		return &dns.Msg{Answer: rr}
	}
	ctx := utils.NewCtx(nil, 0xffff)
	allMatcher := matcher.NewABPByText("*")
	errCaller := newFakeCaller(0, nil, errors.New("call error"))
	hostsReader := hosts.NewReaderByText("127.0.0.1 baidu.com")
	dnsCache := cache.NewDNSCache(100, time.Minute, time.Hour)
	groups := make(map[string]*Group)
	// endregion

	utils.CtxInfo(ctx, "---- test begin ----")
	server := NewDNSServer("", "", []string{"NS"}, nil, dnsCache, nil)

	writer.Msg = nil
	server.ServeDNS(writer, &dns.Msg{Question: []dns.Question{}})
	assert.Empty(t, writer.Msg.Answer)

	writer.Msg = nil
	server.ServeDNS(writer, newReq("abc", dns.TypeNS))
	assert.Empty(t, writer.Msg.Answer)

	writer.Msg = nil
	server.ServeDNS(writer, newReq("abc", dns.TypeA))
	assert.Empty(t, writer.Msg.Answer)

	utils.CtxInfo(ctx, "---- test call err ----")
	groups["all"] = NewGroup("all", allMatcher, []outbound.Caller{errCaller})
	server = NewDNSServer("", "", nil, nil, dnsCache, groups)

	writer.Msg = nil
	server.ServeDNS(writer, newReq("abc", dns.TypeA))
	assert.Empty(t, writer.Msg.Answer)

	utils.CtxInfo(ctx, "---- test hit hosts ----")
	groups["all"] = NewGroup("all", allMatcher, []outbound.Caller{errCaller})
	_h := []hosts.Reader{hostsReader}
	server = NewDNSServer("", "", nil, _h, dnsCache, groups)

	writer.Msg = nil
	server.ServeDNS(writer, newReq("BAIDU.COM.", dns.TypeA))
	assert.NotEmpty(t, writer.Msg.Answer)

	mocker.Method(hostsReader, "Record", func(*hosts.TextReader, string, bool) string {
		return "invalid string"
	})
	writer.Msg = nil
	server.ServeDNS(writer, newReq("BAIDU.COM.", dns.TypeA))
	assert.Empty(t, writer.Msg.Answer)

	utils.CtxInfo(ctx, "---- test hit cache ----")
	caller := newOneTimeCaller(newResp([]dns.RR{&dns.A{A: []byte{1, 1, 1, 1}}}))
	groups["all"] = NewGroup("all", allMatcher, []outbound.Caller{caller})
	server = NewDNSServer("", "", nil, nil, dnsCache, groups)

	writer.Msg = nil
	server.ServeDNS(writer, newReq("BAIDU.COM.", dns.TypeA))
	assert.NotEmpty(t, writer.Msg.Answer)
	writer.Msg = nil
	server.ServeDNS(writer, newReq("BAIDU.COM.", dns.TypeA))
	assert.NotEmpty(t, writer.Msg.Answer)
}
