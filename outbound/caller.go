package outbound

import (
	"bytes"
	"crypto/tls"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"net"
	"net/http"
)

// Caller 上游DNS请求基类
type Caller interface {
	Call(request *dns.Msg) (r *dns.Msg, err error)
}

// DNSCaller UDP/TCP/DOT请求类
type DNSCaller struct {
	client *dns.Client
	server string
	proxy  proxy.Dialer
	conn   *dns.Conn
}

// Call 向目标上游DNS转发请求
func (caller *DNSCaller) Call(request *dns.Msg) (r *dns.Msg, err error) {
	if caller.proxy == nil { // 不使用代理，直接发送dns请求
		r, _, err = caller.client.Exchange(request, caller.server)
		return
	}
	// 通过代理连接代理服务器
	var proxyConn net.Conn
	if proxyConn, err = caller.proxy.Dial("tcp", caller.server); err != nil {
		return nil, err
	}
	defer func() { _ = proxyConn.Close() }()
	// 打包连接
	caller.conn.Conn = proxyConn
	if caller.client.TLSConfig != nil { // dns over tls
		caller.conn.Conn = tls.Client(proxyConn, caller.client.TLSConfig)
	}
	// 发送dns请求
	if err = caller.conn.WriteMsg(request); err != nil {
		return nil, err
	}
	return caller.conn.ReadMsg()
}

// NewDNSCaller 创建一个UDP/TCP Caller，需要服务器地址（ip+端口）、网络类型（udp、tcp），可选代理
func NewDNSCaller(server, network string, proxy proxy.Dialer) *DNSCaller {
	client := &dns.Client{Net: network}
	return &DNSCaller{client: client, server: server, proxy: proxy, conn: &dns.Conn{}}
}

// NewDoTCaller 创建一个DoT Caller，需要服务器地址（ip+端口）、证书名称，可选代理
func NewDoTCaller(server, serverName string, proxy proxy.Dialer) *DNSCaller {
	client := &dns.Client{Net: "tcp-tls", TLSConfig: &tls.Config{ServerName: serverName}}
	return &DNSCaller{client: client, server: server, proxy: proxy, conn: &dns.Conn{}}
}

// DoHCaller DoT请求类
type DoHCaller struct {
	client *http.Client
	url    string
}

// Call 向上游DNS转发请求
func (caller *DoHCaller) Call(request *dns.Msg) (r *dns.Msg, err error) {
	// 打包请求
	var buf []byte
	if buf, err = request.Pack(); err != nil {
		return nil, err
	}
	// 发送请求
	var resp *http.Response
	contentType, payload := "application/dns-message", bytes.NewBuffer(buf)
	if resp, err = caller.client.Post(caller.url, contentType, payload); err != nil {
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

// NewDoHCaller 创建一个DoH Caller，需要服务器url（https://domain/dns-query），可选代理
func NewDoHCaller(url string, proxy proxy.Dialer) *DoHCaller {
	client := &http.Client{}
	if proxy != nil {
		client.Transport = &http.Transport{Dial: proxy.Dial}
	}
	return &DoHCaller{client: client, url: url}
}
