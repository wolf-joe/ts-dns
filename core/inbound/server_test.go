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
	allM := matcher.NewABPByText("*")
	cErr := newFakeCaller(0, nil, errors.New("err"))
	groups := map[string]*Group{"test": NewGroup("test", allM, []outbound.Caller{cErr})}
	logCfg := NewLogConfig(nil, nil, false, false)
	server := NewDNSServer("127.0.0.1:5353", "", groups, logCfg)

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
	server = NewDNSServer("127.0.0.1:5353", "udp", groups, logCfg)
	mockShutdownContext(mocker, "system is busy")
	server.Run(ctx)
	time.Sleep(20 * time.Millisecond)
	server.StopAndWait()

	assert.Equal(t, groups["test"], server.GetGroup("test"))
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
	logCfg := NewLogConfig(nil, nil, false, false)
	groups := make(map[string]*Group)
	// endregion

	utils.CtxInfo(ctx, "---- test begin ----")
	server := NewDNSServer("", "", nil, logCfg)
	server.SetDisableQTypes([]string{"NS"})

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
	server = NewDNSServer("", "", groups, logCfg)

	writer.Msg = nil
	server.ServeDNS(writer, newReq("abc", dns.TypeA))
	assert.Empty(t, writer.Msg.Answer)

	utils.CtxInfo(ctx, "---- test hit hosts ----")
	groups["all"] = NewGroup("all", allMatcher, []outbound.Caller{errCaller})
	hostsReader := hosts.NewReaderByText("127.0.0.1 baidu.com")
	server = NewDNSServer("", "", groups, logCfg)
	server.Hosts = []hosts.Reader{hostsReader}

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
	server = NewDNSServer("", "", groups, logCfg)
	server.Cache = cache.NewDNSCache(100, time.Minute, time.Hour)

	writer.Msg = nil
	server.ServeDNS(writer, newReq("BAIDU.COM.", dns.TypeA))
	assert.NotEmpty(t, writer.Msg.Answer)
	writer.Msg = nil
	server.ServeDNS(writer, newReq("BAIDU.COM.", dns.TypeA))
	assert.NotEmpty(t, writer.Msg.Answer)
}

type bufCloser struct {
	buf      []byte
	closeErr error
}

func newBufCloser(closeErr error) *bufCloser {
	return &bufCloser{buf: make([]byte, 0, 4096), closeErr: closeErr}
}
func (b *bufCloser) Write(p []byte) (n int, err error) {
	b.buf = append(b.buf, p...)
	return len(p), nil
}
func (b *bufCloser) Close() error {
	return b.closeErr
}

func TestNewLogConfig(t *testing.T) {
	// region init
	logrus.SetLevel(logrus.InfoLevel)
	logBuf := newBufCloser(errors.New("system busy"))
	logCfg := NewLogConfig(logBuf, []string{"A"}, true, true)
	writer := utils.NewFakeRespWriter()
	newReq := func(name string, qType uint16) *dns.Msg {
		msg := &dns.Msg{Question: []dns.Question{{
			Name: name, Qtype: qType,
		}}}
		msg.Id = uint16(fastrand.Uint32())
		return msg
	}
	ctx := utils.NewCtx(nil, 0xffff)
	matchAll := matcher.NewABPByText("*")
	resp := &dns.Msg{Answer: []dns.RR{&dns.A{A: []byte{1, 1, 1, 1}}}}
	callers := []outbound.Caller{newFakeCaller(0, resp, nil)}
	groups := map[string]*Group{"all": NewGroup("all", matchAll, callers)}
	svc := NewDNSServer("", "", groups, logCfg)
	// endregion

	svc.Hosts = []hosts.Reader{hosts.NewReaderByText("1.2.3.4 baidu.com")}
	req := newReq("baidu.com", dns.TypeA) // hit hosts
	writer.Msg = nil
	logBuf.buf = nil
	svc.ServeDNS(writer, req)
	assert.Equal(t, "1.2.3.4", writer.Msg.Answer[0].(*dns.A).A.String())
	assert.Empty(t, logBuf.buf) // hit hosts, empty log

	req = newReq("ip.cn", dns.TypeA)
	writer.Msg = nil
	logBuf.buf = nil
	svc.ServeDNS(writer, req)
	assert.Equal(t, "1.1.1.1", writer.Msg.Answer[0].(*dns.A).A.String())
	assert.Empty(t, logBuf.buf) // ignore qTypes, empty log

	req = newReq("ip.cn", dns.TypeAAAA)
	writer.Msg = nil
	logBuf.buf = nil
	svc.ServeDNS(writer, req)
	assert.Equal(t, "1.1.1.1", writer.Msg.Answer[0].(*dns.A).A.String())
	assert.NotEmpty(t, logBuf.buf) // log info

	writer.Msg = nil
	logBuf.buf = nil
	svc.ServeDNS(writer, req)
	assert.Equal(t, "1.1.1.1", writer.Msg.Answer[0].(*dns.A).A.String())
	assert.Empty(t, logBuf.buf) // hit cache, empty log

	logCfg.Exit(ctx)
}
