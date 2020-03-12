package DNSCaller

import (
	"bytes"
	"crypto/tls"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"net"
	"net/http"
)

var udpClient = dns.Client{Net: "udp"}
var tcpClient = dns.Client{Net: "tcp"}
var httpClient = http.Client{}

type Caller interface {
	Call(request *dns.Msg) (r *dns.Msg, err error)
}

func call(client dns.Client, request *dns.Msg, address string, dialer proxy.Dialer) (r *dns.Msg, err error) {
	msg := dns.Msg{Question: request.Question, Extra: request.Extra}
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
	dialer  proxy.Dialer
}

func (caller *UDPCaller) Call(request *dns.Msg) (r *dns.Msg, err error) {
	return call(udpClient, request, caller.address, caller.dialer)
}

type TCPCaller struct {
	address string
	dialer  proxy.Dialer
}

func (caller *TCPCaller) Call(request *dns.Msg) (r *dns.Msg, err error) {
	return call(tcpClient, request, caller.address, caller.dialer)
}

type TLSCaller struct {
	address string
	dialer  proxy.Dialer
	client  dns.Client
}

func (caller *TLSCaller) Call(request *dns.Msg) (r *dns.Msg, err error) {
	return call(caller.client, request, caller.address, caller.dialer)
}

func NewTLSCaller(address string, dialer proxy.Dialer,
	serverName string, skipVerify bool) *TLSCaller {
	client := dns.Client{Net: "tcp-tls", TLSConfig: &tls.Config{
		ServerName: serverName, InsecureSkipVerify: skipVerify,
	}}
	caller := &TLSCaller{address: address, dialer: dialer, client: client}
	return caller
}

type DoHCaller struct {
	url    string
	dialer proxy.Dialer
}

func (caller *DoHCaller) Call(request *dns.Msg) (r *dns.Msg, err error) {
	// 打包请求
	var buf []byte
	if buf, err = request.Pack(); err != nil {
		return nil, err
	}
	if caller.dialer != nil { // 使用代理
		httpClient.Transport = &http.Transport{Dial: caller.dialer.Dial}
	}
	// 发送请求
	var resp *http.Response
	contentType, payload := "application/dns-message", bytes.NewBuffer(buf)
	if resp, err = httpClient.Post(caller.url, contentType, payload); err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// 读取响应
	var body []byte
	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		return nil, err
	}
	// 解包响应
	msg := new(dns.Msg)
	if err = msg.Unpack(body); err != nil {
		return nil, err
	}
	return msg, nil
}
