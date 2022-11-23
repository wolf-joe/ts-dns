package core

import "github.com/miekg/dns"

type IGroup interface {
	Handle(req *dns.Msg) *dns.Msg
	Match(req *dns.Msg) bool
	Start()
	Stop()
}

type IRedirector interface {
	Redirect(req *dns.Msg, resp *dns.Msg) IGroup
}
