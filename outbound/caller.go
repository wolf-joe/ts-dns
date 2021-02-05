package outbound

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/valyala/fastrand"
	"github.com/wolf-joe/ts-dns/core/common"
	mock "github.com/wolf-joe/ts-dns/core/mocker"
	"golang.org/x/net/proxy"
)

// Caller 上游DNS请求基类
type Caller interface {
	Call(request *dns.Msg) (r *dns.Msg, err error)
	String() string
	Exit()
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

// Exit caller退出时行为
func (caller *DNSCaller) Exit() {}

// String 描述caller
func (caller *DNSCaller) String() string {
	return fmt.Sprintf("DNSCaller<%s/%s>", caller.server, caller.client.Net)
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

// DoHCaller DoT请求类，Servers和Host暴露给外部方便覆盖.Resolve行为
type DoHCaller struct {
	client  *http.Client
	url     string
	Servers []string
	port    string
	Host    string
}

// Resolve 通过解析.Host（服务器域名）填充.Servers（服务器ip列表），创建对象后只需要调用一次
func (caller *DoHCaller) Resolve() (err error) {
	var ips []net.IP
	if ips, err = net.LookupIP(caller.Host); err != nil {
		return err
	}
	for _, ip := range ips {
		if ip.To4().String() != "<nil>" {
			caller.Servers = append(caller.Servers, ip.To4().String())
		}
	}
	if len(caller.Servers) <= 0 {
		return fmt.Errorf("ip not found")
	}
	return nil
}

// Call 向上游DNS转发请求
func (caller *DoHCaller) Call(request *dns.Msg) (r *dns.Msg, err error) {
	if len(caller.Servers) <= 0 {
		return nil, fmt.Errorf("need call .Resolve() first")
	}
	// 解包dns请求
	var buf []byte
	if buf, err = request.Pack(); err != nil {
		return nil, err
	}
	// 打包http请求
	var req *http.Request
	contentType, payload := "application/dns-message", bytes.NewBuffer(buf)
	if req, err = http.NewRequest("POST", caller.url, payload); err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	// 发送http请求
	var resp *http.Response
	if resp, err = caller.client.Do(req); err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// 解包http响应
	var body []byte
	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		return nil, err
	}
	// 打包dns响应
	msg := new(dns.Msg)
	if err = msg.Unpack(body); err != nil {
		return nil, err
	}
	return msg, nil
}

// Exit caller退出时行为
func (caller *DoHCaller) Exit() {}

// String 描述caller
func (caller *DoHCaller) String() string {
	return fmt.Sprintf("DoHCaller<%s>", caller.url)
}

// NewDoHCaller 创建一个DoH Caller，需要服务器url，可选代理。创建完成后还需要调用.Resolve才能Call
func NewDoHCaller(rawURL string, proxy proxy.Dialer) (caller *DoHCaller, err error) {
	// 解析url
	var u *url.URL
	if u, err = url.Parse(rawURL); err != nil {
		return nil, err
	}
	if !u.IsAbs() {
		return nil, fmt.Errorf("rawURL should be abs url")
	}
	// 提取host、port、path
	var host, port string
	if i := strings.LastIndex(u.Host, ":"); i == -1 {
		u.Host += ":443"
	}
	if host, port, err = net.SplitHostPort(u.Host); err != nil {
		return nil, err
	}
	if proxy == nil {
		proxy = &net.Dialer{Timeout: time.Second * 3}
	}
	// 自定义DialContext，用于指定目标ip
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
		addr = caller.Servers[rand.Intn(len(caller.Servers))] + ":" + caller.port
		return proxy.Dial(network, addr)
	}}}
	return &DoHCaller{client: client, port: port, url: u.String(), Host: host}, nil
}

// DoHCallerV2 DoT请求类，通过resolver自动解析域名
type DoHCallerV2 struct {
	host     string
	port     string
	url      string
	clients  []*http.Client
	rwMux    sync.RWMutex
	resolver dns.Handler
	dialer   proxy.Dialer

	satisfyCh chan interface{} // 域名解析完成
	requireCh chan interface{} // 要求解析域名
	cancelCh  chan interface{} // stop run()
}

// 后台goroutine，负责定时/按需解析DoH服务器域名
func (caller *DoHCallerV2) run(tick <-chan time.Time, timeout time.Duration) {
	fl := common.FileLocStr
	log.Debugf("[%s] %s run", fl(), caller)
	for {
		select {
		case <-tick:
			caller.rwMux.Lock()
			caller.resolve(timeout)
			caller.rwMux.Unlock()
		case <-caller.requireCh: // getClient()触发
			caller.rwMux.Lock()
			if len(caller.clients) == 0 {
				caller.resolve(timeout)
			}
			caller.rwMux.Unlock()
			caller.satisfyCh <- struct{}{} // 通知getClient()
		case <-caller.cancelCh:
			log.Debugf("[%s] %s stopped", fl(), caller)
			return
		}
	}
}

// Exit 停止后台goroutine。caller退出时行为
func (caller *DoHCallerV2) Exit() {
	caller.cancelCh <- struct{}{}
}

// String 描述caller
func (caller *DoHCallerV2) String() string {
	return fmt.Sprintf("DoHCallerV2<%s>", caller.url)
}

// 使用resolver，将host解析成ipv4并生成clients
func (caller *DoHCallerV2) resolve(timeout time.Duration) {
	fl := common.FileLocStr
	genClient := func(ip string) *http.Client {
		return &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
				addr = ip + ":" + caller.port // 重写addr
				return caller.dialer.Dial(network, addr)
			},
		}}
	}
	name := caller.host + "."
	// 模拟dns请求
	req := &dns.Msg{
		MsgHdr:   dns.MsgHdr{Id: 0xffff, RecursionDesired: true, AuthenticatedData: true},
		Question: []dns.Question{{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}},
	}
	writer := &mock.FakeRespWriter{}
	done := make(chan interface{}, 1)
	go func() {
		if caller.resolver != nil {
			caller.resolver.ServeDNS(writer, req)
		}
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		log.Warnf("[%s] %s resolve timeout", fl(), caller)
		return // 超时直接结束
	}
	// 解析响应中的ipv4地址
	clients := make([]*http.Client, 0, 2)
	ips := make([]string, 0, 2)
	if writer.Msg != nil {
		for _, rr := range writer.Msg.Answer {
			switch resp := rr.(type) {
			case *dns.A:
				clients = append(clients, genClient(resp.A.String()))
				ips = append(ips, resp.A.String())
			}
		}
	}
	if len(clients) > 0 {
		caller.clients = clients
		log.Debugf("[%s] %s resolve %s", fl(), caller, ips)
	} else {
		log.Warnf("[%s] %s resolve failed", fl(), caller)
	}
}

// 获取一个用于发送DoH查询请求的http客户端
func (caller *DoHCallerV2) getClient() *http.Client {
	caller.rwMux.RLock()
	defer caller.rwMux.RUnlock()
	var n int
	if n = len(caller.clients); n == 0 { // 域名未解析
		caller.rwMux.RUnlock()
		caller.requireCh <- struct{}{} // 要求解析域名
		<-caller.satisfyCh             // 等待解析完成
		caller.rwMux.RLock()
		if n = len(caller.clients); n == 0 {
			return nil
		}
		goto CHOICE
	}
CHOICE:
	return caller.clients[fastrand.Uint32n(uint32(n))]
}

// Call 向上游DNS转发请求
func (caller *DoHCallerV2) Call(request *dns.Msg) (r *dns.Msg, err error) {
	client := caller.getClient()
	if client == nil {
		return nil, errors.New("empty client for doh caller")
	}
	// 解包dns请求
	var buf []byte
	if buf, err = request.Pack(); err != nil {
		return nil, err
	}
	// 打包http请求
	var req *http.Request
	contentType, payload := "application/dns-message", bytes.NewBuffer(buf)
	if req, err = http.NewRequest("POST", caller.url, payload); err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	// 发送http请求
	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// 解包http响应
	var body []byte
	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		return nil, err
	}
	// 打包dns响应
	msg := new(dns.Msg)
	if err = msg.Unpack(body); err != nil {
		return nil, err
	}
	return msg, nil
}

// SetResolver 为DoHCaller设置域名解析器，需要在用NewDoHCallerV2()成功后调用一次
func (caller *DoHCallerV2) SetResolver(resolver dns.Handler) {
	caller.resolver = resolver
}

// NewDoHCallerV2 创建一个DoHCaller，需要服务器url，可选代理
func NewDoHCallerV2(rawURL string, dialer proxy.Dialer) (*DoHCallerV2, error) {
	// 解析url
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if !u.IsAbs() {
		return nil, fmt.Errorf("rawURL should be abs url")
	}
	// 提取host、port
	var host, port string
	if i := strings.LastIndex(u.Host, ":"); i == -1 {
		u.Host += ":443"
	}
	if host, port, err = net.SplitHostPort(u.Host); err != nil {
		return nil, err
	}

	if dialer == nil {
		dialer = &net.Dialer{Timeout: time.Second * 3}
	}
	caller := &DoHCallerV2{host: host, port: port, url: u.String(),
		rwMux: sync.RWMutex{}, dialer: dialer}
	caller.requireCh = make(chan interface{}, 1)
	caller.satisfyCh = make(chan interface{}, 1)
	caller.cancelCh = make(chan interface{}, 1)
	go caller.run(time.Tick(time.Hour*24), time.Second)
	return caller, nil
}
