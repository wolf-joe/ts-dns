package DNSCaller

import (
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"net"
)

var dnsClient = new(dns.Client)

type Caller interface {
	Call(question dns.Question, extra []dns.RR, dialer proxy.Dialer) (r *dns.Msg, err error)
}

type UDPCaller struct {
	address string
}

func (caller *UDPCaller) Call(question dns.Question,
	extra []dns.RR, dialer proxy.Dialer) (r *dns.Msg, err error) {
	msg := dns.Msg{}
	msg.Extra = extra
	msg.SetQuestion(question.Name, question.Qtype)

	var proxyConn net.Conn
	// 返回前关闭代理连接
	defer func() {
		if proxyConn != nil {
			_ = proxyConn.Close()
		}
	}()
	if dialer != nil {
		// 使用代理连接DNS服务器
		if proxyConn, err = dialer.Dial("tcp", caller.address); err != nil {
			return nil, err
		} else {
			conn := &dns.Conn{Conn: proxyConn}
			if err = conn.WriteMsg(&msg); err != nil {
				return nil, err
			}
			return conn.ReadMsg()
		}
	} else {
		// 不使用代理
		r, _, err = dnsClient.Exchange(&msg, caller.address)
		return r, err
	}
}
