package outbound

import "github.com/miekg/dns"

var (
	_ IGroup = MockGroup{}
)

type MockGroup struct {
	MockMatch       func(msg *dns.Msg) bool
	MockIsFallback  func() bool
	MockHandle      func(req *dns.Msg) *dns.Msg
	MockPostProcess func(req, resp *dns.Msg)
	MockStart       func(resolver dns.Handler)
	MockStop        func()
	MockName        func() string
	MockString      func() string
}

func (m MockGroup) Match(req *dns.Msg) bool                 { return m.MockMatch(req) }
func (m MockGroup) IsFallback() bool                        { return m.MockIsFallback() }
func (m MockGroup) Handle(req *dns.Msg) *dns.Msg            { return m.MockHandle(req) }
func (m MockGroup) PostProcess(req *dns.Msg, resp *dns.Msg) { m.MockPostProcess(req, resp) }
func (m MockGroup) Start(resolver dns.Handler)              { m.MockStart(resolver) }
func (m MockGroup) Stop()                                   { m.MockStop() }
func (m MockGroup) Name() string                            { return m.MockName() }
func (m MockGroup) String() string                          { return m.MockString() }
