package outbound

import "github.com/miekg/dns"

var (
	_ IGroup = MockGroup{}
)

type MockGroup struct {
	MockName   func() string
	MockString func() string
}

func (m MockGroup) Match(req *dns.Msg) bool {
	//TODO implement me
	panic("implement me")
}

func (m MockGroup) IsFallback() bool {
	//TODO implement me
	panic("implement me")
}

func (m MockGroup) Handle(req *dns.Msg) *dns.Msg {
	//TODO implement me
	panic("implement me")
}

func (m MockGroup) PostProcess(req *dns.Msg, resp *dns.Msg) {
	//TODO implement me
	panic("implement me")
}

func (m MockGroup) Start(resolver dns.Handler) {
	//TODO implement me
	panic("implement me")
}

func (m MockGroup) Stop() {
	//TODO implement me
	panic("implement me")
}

func (m MockGroup) Name() string   { return m.MockName() }
func (m MockGroup) String() string { return m.MockString() }
