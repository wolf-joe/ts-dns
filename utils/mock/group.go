package mock

import (
	"github.com/miekg/dns"
)

type Group struct {
	MockMatch       func(msg *dns.Msg) bool
	MockIsFallback  func() bool
	MockHandle      func(req *dns.Msg) *dns.Msg
	MockPostProcess func(req, resp *dns.Msg)
	MockStart       func(resolver dns.Handler)
	MockStop        func()
	MockName        func() string
	MockString      func() string
}

func (m Group) Match(req *dns.Msg) bool                 { return m.MockMatch(req) }
func (m Group) IsFallback() bool                        { return m.MockIsFallback() }
func (m Group) Handle(req *dns.Msg) *dns.Msg            { return m.MockHandle(req) }
func (m Group) PostProcess(req *dns.Msg, resp *dns.Msg) { m.MockPostProcess(req, resp) }
func (m Group) Start(resolver dns.Handler)              { m.MockStart(resolver) }
func (m Group) Stop()                                   { m.MockStop() }
func (m Group) Name() string                            { return m.MockName() }
func (m Group) String() string                          { return m.MockString() }
