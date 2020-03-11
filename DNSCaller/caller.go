package DNSCaller

import (
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"net"
)

var udpClient = dns.Client{Net: "udp"}
var tcpClient = dns.Client{Net: "tcp"}

type Caller interface {
	Call(question dns.Question, extra []dns.RR, dialer proxy.Dialer) (r *dns.Msg, err error)
}

func call(client dns.Client, address string, question dns.Question,
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
		if proxyConn, err = dialer.Dial("tcp", address); err != nil {
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
		r, _, err = client.Exchange(&msg, address)
		return r, err
	}
}

type UDPCaller struct {
	address string
}

func (caller *UDPCaller) Call(question dns.Question,
	extra []dns.RR, dialer proxy.Dialer) (r *dns.Msg, err error) {
	return call(udpClient, caller.address, question, extra, dialer)
}

type TCPCaller struct {
	address string
}

func (caller *TCPCaller) Call(question dns.Question,
	extra []dns.RR, dialer proxy.Dialer) (r *dns.Msg, err error) {
	return call(tcpClient, caller.address, question, extra, dialer)
}
