package inbound

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/go-ipset/ipset"
	"github.com/wolf-joe/ts-dns/core/utils"
	"github.com/wolf-joe/ts-dns/core/utils/mock"
	"github.com/wolf-joe/ts-dns/outbound"
)

type fakeCaller struct {
	latestReq *dns.Msg
	sleep     time.Duration
	resp      *dns.Msg
	err       error
}

func (f *fakeCaller) Call(req *dns.Msg) (r *dns.Msg, err error) {
	f.latestReq = req
	time.Sleep(f.sleep)
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func (f *fakeCaller) Exit() {
}

func (f *fakeCaller) String() string {
	return fmt.Sprintf("fakeCaller<%s,%p,%p>", f.sleep, f.resp, f.err)
}

func newFakeCaller(sleep time.Duration, resp *dns.Msg, err error) *fakeCaller {
	return &fakeCaller{sleep: sleep, resp: resp, err: err}
}

func TestGroup(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	ctx := utils.NewCtx(nil, 0xffff)
	req := &dns.Msg{Question: []dns.Question{{Qtype: dns.TypeA}}}
	mockResp := &dns.Msg{Answer: []dns.RR{&dns.A{A: []byte{1, 1, 1, 1}}}}
	cErr := newFakeCaller(50*time.Millisecond, nil, errors.New("err by mock"))
	cMock := newFakeCaller(100*time.Millisecond, mockResp, nil)
	cNil := newFakeCaller(100*time.Millisecond, nil, nil)

	group := NewGroup("test", nil, nil)
	fmt.Println(group)
	assert.Nil(t, group.Handle(ctx, req, nil))

	group = NewGroup("test", nil, []outbound.Caller{cErr, cMock})
	assert.Equal(t, mockResp, group.Handle(ctx, req, nil))

	// 0. test next
	fmt.Println("test Next")
	group.Next = &copyRespHandler{}
	assert.NotEqual(t, mockResp, group.Handle(ctx, req, nil))
	group.Next = &toNextHandler{next: group}
	assert.NotEqual(t, mockResp, group.Handle(ctx, req, nil))

	// 1. test Concurrent
	fmt.Println("test Concurrent")
	group.Next = nil
	group.Concurrent = true
	assert.Equal(t, mockResp, group.Handle(ctx, req, nil))

	group = NewGroup("test", nil, []outbound.Caller{cErr, cNil})
	group.Concurrent = true
	assert.Nil(t, group.Handle(ctx, req, nil))

	// 2. test WithFastestIP
	fmt.Println("test WithFastestIP")
	group = NewGroup("test", nil, []outbound.Caller{cErr, cNil})
	group.WithFastestIP(0)
	assert.Nil(t, group.Handle(ctx, req, nil))

	group = NewGroup("test", nil, []outbound.Caller{cErr, cMock})
	group.WithFastestIP(0)
	assert.Equal(t, mockResp, group.Handle(ctx, req, nil))

	mocker := new(mock.Mocker)
	defer mocker.Reset()
	mockPing := func(ip string, err error) {
		mocker.Func(utils.FastestPingIP, func(_ context.Context, _ []string, _ int, _ time.Duration,
		) (string, int64, error) {
			return ip, 233, err
		})
	}
	buildAnswer := func(v6 bool) {
		mockResp.Answer = nil
		for i := byte(1); i < 20; i++ {
			var rr dns.RR
			rr = &dns.A{A: []byte{1, 1, 1, i}}
			if v6 {
				rr = &dns.AAAA{AAAA: append(make([]byte, 10), []byte{0xff, 0xff, 1, 1, 1, i}...)}
			}
			mockResp.Answer = append(mockResp.Answer, rr)
		}
	}
	buildAnswer(false)
	mockPing("", errors.New("timeout"))
	assert.Equal(t, mockResp, group.Handle(ctx, req, nil))

	buildAnswer(false)
	mockPing("1.1.1.1", nil)
	resp := group.Handle(ctx, req, nil)
	assert.NotNil(t, resp)
	assert.Equal(t, 1, len(mockResp.Answer))

	req.Question[0].Qtype = dns.TypeAAAA
	buildAnswer(true)
	assert.Equal(t, mockResp, group.Handle(ctx, req, nil))
}

func TestGroup2(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	ctx := utils.NewCtx(nil, 0xffff)
	req := &dns.Msg{Question: []dns.Question{{Qtype: dns.TypeA}}}
	mockResp := &dns.Msg{Answer: []dns.RR{&dns.A{A: []byte{1, 1, 1, 1}}}}
	c := newFakeCaller(100*time.Millisecond, mockResp, nil)

	group := NewGroup("test", nil, []outbound.Caller{c})
	next := &copyRespHandler{}
	group.Next = next

	c.latestReq, next.latestReq = nil, nil
	_ = group.Handle(ctx, req, nil)
	assert.NotNil(t, c.latestReq)
	assert.NotNil(t, next.latestReq)
	assert.Equal(t, c.latestReq, next.latestReq)

	group.NoCookie = true
	_ = group.Handle(ctx, req, nil)
	assert.NotNil(t, c.latestReq)
	assert.NotNil(t, next.latestReq)
	assert.NotEqual(t, c.latestReq, next.latestReq)

	group.NoCookie = false
	group.WithECS = &dns.EDNS0_SUBNET{}
	_ = group.Handle(ctx, req, nil)
	assert.NotNil(t, c.latestReq)
	assert.NotNil(t, next.latestReq)
	assert.NotEqual(t, c.latestReq, next.latestReq)

	// test with ipset
	mockResp.Answer = append(mockResp.Answer, &dns.A{A: []byte{1, 1, 1, 2}})
	group = NewGroup("test", nil, []outbound.Caller{c})
	group.IPSet = &ipset.IPSet{}
	mocker := new(mock.Mocker)
	defer mocker.Reset()
	mocker.Method(group.IPSet, "Add", func(_ *ipset.IPSet, entry string, _ int) error {
		if entry == "1.1.1.1" {
			return nil
		}
		return errors.New("err by mock")
	})
	_ = group.Handle(ctx, req, nil)
	time.Sleep(10 * time.Millisecond) // wait ipset goroutine done
}
