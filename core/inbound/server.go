package inbound

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/core/utils"
	"github.com/wolf-joe/ts-dns/hosts"
)

// DNSServer 程序主体，负责Hosts/缓存/请求分发
type DNSServer struct {
	listen   string           // 监听地址
	network  string           // 监听协议
	stopSign chan interface{} // 服务停止信号
	stopped  chan interface{} // 服务是否停止

	disableQTypes map[uint16]bool // 禁用的DNS查询类型
	hosts         []*hosts.Reader
	cache         *cache.DNSCache // DNS响应缓存

	groups map[string]*Group
}

// NewDNSServer 创建一个DNS Server
func NewDNSServer(listen, network string, disableQTypes []string, hosts []*hosts.Reader,
	cache *cache.DNSCache, groups map[string]*Group) *DNSServer {
	qTypes := make(map[uint16]bool, len(disableQTypes))
	for _, qTypeStr := range disableQTypes {
		if qType, exists := dns.StringToType[strings.ToUpper(qTypeStr)]; exists {
			qTypes[qType] = true
		}
	}
	return &DNSServer{
		listen: listen, network: network, disableQTypes: qTypes,
		hosts: hosts, cache: cache, groups: groups,
	}
}

// Run 以阻塞形式启动DNS Server
func (s *DNSServer) Run(ctx context.Context) {
	s.stopSign = make(chan interface{}, 0)
	s.stopped = make(chan interface{}, 0)
	errCh := make(chan error, 2)
	newSrv := func(net string) *dns.Server { return &dns.Server{Addr: s.listen, Net: net, Handler: s} }
	servers := make([]*dns.Server, 0, 2)
	if s.network != "" {
		servers = append(servers, newSrv(s.network))
	} else {
		servers = append(servers, newSrv("tcp"))
		servers = append(servers, newSrv("udp"))
	}
	go s.wait(ctx, servers, errCh)
}

//
func (s *DNSServer) wait(ctx context.Context, servers []*dns.Server, errCh chan error) {
	utils.CtxDebug(ctx, "%s is running", s)
	for _, srv := range servers {
		go func(srv *dns.Server) {
			select {
			case <-s.stopSign:
				return
			default:
				// continue
			}
			utils.CtxWarn(ctx, "listen on %s/%s", srv.Addr, srv.Net)
			if err := srv.ListenAndServe(); err != nil {
				utils.CtxError(ctx, err.Error())
				errCh <- err
			}
		}(srv)
	}
	// 阻塞运行
	for alive := len(servers); alive > 0; {
		select {
		case <-errCh:
			alive--
		case <-s.stopSign:
			for _, svr := range servers {
				if err := svr.ShutdownContext(ctx); err != nil {
					utils.CtxError(ctx, err.Error())
				}
			}
			alive = 0
		}
	}
	utils.CtxDebug(ctx, "%s is stopped", s)
	close(s.stopped)
}

// StopAndWait 以阻塞形式停止DNS Server
func (s *DNSServer) StopAndWait() {
	close(s.stopSign)
	<-s.stopped
}

// String 描述DNS Server
func (s *DNSServer) String() string {
	return fmt.Sprintf("DNSServer<%s/%s>", s.listen, s.network)
}

func (s *DNSServer) ServeDNS(writer dns.ResponseWriter, req *dns.Msg) {
	ctx := utils.NewCtx(nil, req.Id)
	utils.CtxDebug(ctx, "request: %q", req.Question)

	var resp *dns.Msg
	defer func() { // 返回响应
		if resp == nil {
			resp = &dns.Msg{}
		}
		utils.CtxDebug(ctx, "response: %q", resp.Answer)
		resp.SetReply(req)
		_ = writer.WriteMsg(resp)
		_ = writer.Close()
	}()

	if len(req.Question) == 0 {
		return
	}
	question := req.Question[0]
	if s.disableQTypes[question.Qtype] {
		return
	}

	for _, group := range s.groups {
		if match, ok := group.matcher.Match(question.Name); ok && match {
			resp = group.Handle(ctx, req, nil)
		}
	}
}
