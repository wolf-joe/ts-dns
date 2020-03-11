package DNSCaller

import (
	"crypto/tls"
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
	if dialer == nil {
		// 不使用代理
		r, _, err = client.Exchange(&msg, address)
		return r, err
	}
	// 使用代理连接DNS服务器
	if proxyConn, err = dialer.Dial("tcp", address); err != nil {
		return nil, err
	}
	var conn *dns.Conn
	if client.Net == "tcp" || client.Net == "udp" {
		conn = &dns.Conn{Conn: proxyConn}
	} else { // dns over tls
		conn = &dns.Conn{Conn: tls.Client(proxyConn, client.TLSConfig)}
	}
	if err = conn.WriteMsg(&msg); err != nil {
		return nil, err
	}
	return conn.ReadMsg()

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

type TLSCaller struct {
	address   string
	tlsConfig *tls.Config
}

func (caller *TLSCaller) Call(question dns.Question,
	extra []dns.RR, dialer proxy.Dialer) (r *dns.Msg, err error) {
	client := dns.Client{Net: "tcp-tls", TLSConfig: caller.tlsConfig}
	return call(client, caller.address, question, extra, dialer)
}
