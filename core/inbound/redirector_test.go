package inbound

import (
	"context"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/core/utils"
	"github.com/wolf-joe/ts-dns/matcher"
)

type copyRespHandler struct{}

func (*copyRespHandler) Handle(_ context.Context, _, resp *dns.Msg) *dns.Msg { return resp.Copy() }
func (*copyRespHandler) String() string                                      { return "copyRespHandler" }

type toNextHandler struct{ next Handler }

func (h *toNextHandler) Handle(ctx context.Context, req, resp *dns.Msg) *dns.Msg {
	return h.next.Handle(ctx, req, resp)
}
func (*toNextHandler) String() string { return "toNextHandler" }

func TestIPSetRedirector(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	ctx := utils.NewCtx(nil, 0xffff)
	ramSet := cache.NewRamSetByText("1.1.1.1")
	resp := &dns.Msg{}

	redirector := NewIPRedirector(ramSet, IPRedTypeIfFind, nil)
	assert.Equal(t, resp, redirector.Handle(ctx, nil, resp)) // next not set

	redirector = NewIPRedirector(ramSet, IPRedTypeIfFind, &copyRespHandler{})
	assert.Equal(t, resp, redirector.Handle(ctx, nil, resp)) // not find ip match ramSet

	resp.Answer = append(resp.Answer, &dns.A{A: []byte{1, 1, 1, 1}})
	assert.NotEqual(t, resp, redirector.Handle(ctx, nil, resp)) // find ip, return copy of resp

	resp.Answer = []dns.RR{&dns.AAAA{AAAA: []byte{1, 1, 1, 1, 1, 1, 1, 1}}}
	resp.Answer = append(resp.Answer, &dns.DNAME{})
	redirector = NewIPRedirector(ramSet, IPRedTypeIfNotFind, &copyRespHandler{})
	assert.NotEqual(t, resp, redirector.Handle(ctx, nil, resp)) // not find ip, return copy of resp

	// test recursive
	redirector.next = &toNextHandler{next: redirector}
	assert.Equal(t, resp, redirector.Handle(ctx, nil, resp))
}

func TestDomainRedirector(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	ctx := utils.NewCtx(nil, 0xffff)
	rules := matcher.NewABPByText("a.com")
	req, resp := &dns.Msg{}, &dns.Msg{}

	redirector := NewDomainRedirector(rules, DomainRedRuleIfMatch, nil)
	assert.Equal(t, resp, redirector.Handle(ctx, req, resp)) // next not set

	req.Question = []dns.Question{{Name: "A.COM."}}
	redirector = NewDomainRedirector(rules, DomainRedRuleIfMatch, &copyRespHandler{})
	assert.NotEqual(t, resp, redirector.Handle(ctx, req, resp)) // matched, return copy of resp

	req.Question = []dns.Question{{Name: "B.COM."}}
	assert.Equal(t, resp, redirector.Handle(ctx, req, resp)) // not matched, return resp

	redirector = NewDomainRedirector(rules, DomainRedRuleIfNotMatch, &copyRespHandler{})
	assert.NotEqual(t, resp, redirector.Handle(ctx, req, resp)) // not matched, return copy of resp

	// test recursive
	redirector.next = &toNextHandler{next: redirector}
	assert.Equal(t, resp, redirector.Handle(ctx, req, resp))
}
