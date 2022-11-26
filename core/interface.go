package core

import (
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/outbound"
)

type IRedirector interface {
	Redirect(req *dns.Msg, resp *dns.Msg) outbound.IGroup
}
