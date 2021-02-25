package inbound

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fastrand"
	"github.com/wolf-joe/ts-dns/core/utils"
	"github.com/wolf-joe/ts-dns/core/utils/mock"
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

func TestDNSServer_ServeDNS(t *testing.T) {
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

	server := NewDNSServer("", "", []string{"NS"}, nil, nil, nil)

	writer.Msg = nil
	server.ServeDNS(writer, &dns.Msg{Question: []dns.Question{}})
	assert.Empty(t, writer.Msg.Answer)

	writer.Msg = nil
	server.ServeDNS(writer, newReq("abc", dns.TypeNS))
	assert.Empty(t, writer.Msg.Answer)

	writer.Msg = nil
	server.ServeDNS(writer, newReq("abc", dns.TypeA))
	assert.Empty(t, writer.Msg.Answer)

	allMatcher := matcher.NewABPByText("*")
	errCaller := newFakeCaller(0, nil, errors.New("call error"))
	groups := map[string]*Group{"all": NewGroup("all", allMatcher, []outbound.Caller{errCaller})}
	server = NewDNSServer("", "", nil, nil, nil, groups)

	writer.Msg = nil
	server.ServeDNS(writer, newReq("abc", dns.TypeA))
	assert.Empty(t, writer.Msg.Answer)
}
