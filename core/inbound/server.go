package inbound

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/core/utils"
	"github.com/wolf-joe/ts-dns/hosts"
)

// DNSServer 程序主体，负责Hosts/缓存/请求分发
type DNSServer struct {
	addr     string           // 监听地址
	network  string           // 监听协议
	stopSign chan interface{} // 服务停止信号
	stopped  chan interface{} // 服务是否停止

	disableQTypes map[uint16]bool // 禁用的DNS查询类型
	Hosts         []hosts.Reader  // Hosts hosts列表
	Cache         *cache.DNSCache // Cache DNS响应缓存
	logCfg        *LogConfig

	groups map[string]*Group
}

// NewDNSServer 创建一个DNS Server
func NewDNSServer(addr, network string, groups map[string]*Group, logCfg *LogConfig) *DNSServer {
	dnsCache := cache.NewDNSCache(cache.DefaultSize, cache.DefaultMinTTL, cache.DefaultMaxTTL)
	return &DNSServer{addr: addr, network: network, logCfg: logCfg, groups: groups, Cache: dnsCache}
}

// GetGroup 通过group名称获取group
func (s *DNSServer) GetGroup(name string) *Group {
	return s.groups[name]
}

// SetDisableQTypes 设置禁止查询的类型
func (s *DNSServer) SetDisableQTypes(qTypes []string) {
	s.disableQTypes = make(map[uint16]bool, len(qTypes))
	for _, qTypeStr := range qTypes {
		if qType, exists := dns.StringToType[strings.ToUpper(qTypeStr)]; exists {
			s.disableQTypes[qType] = true
		}
	}
}

// Run 以阻塞形式启动DNS Server
func (s *DNSServer) Run(ctx context.Context) {
	s.stopSign = make(chan interface{}, 0)
	s.stopped = make(chan interface{}, 0)
	errCh := make(chan error, 2)
	newSrv := func(net string) *dns.Server { return &dns.Server{Addr: s.addr, Net: net, Handler: s} }
	servers := make([]*dns.Server, 0, 2)
	if s.network != "" {
		servers = append(servers, newSrv(s.network))
	} else {
		servers = append(servers, newSrv("tcp"))
		servers = append(servers, newSrv("udp"))
	}
	go s.wait(ctx, servers, errCh)
}

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
	for _, group := range s.groups {
		group.Exit()
	}
	s.logCfg.Exit(ctx)
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
	return fmt.Sprintf("DNSServer<%s/%s>", s.addr, s.network)
}

// ServeDNS 核心函数，处理DNS查询请求
func (s *DNSServer) ServeDNS(writer dns.ResponseWriter, req *dns.Msg) {
	ctx := utils.NewCtx(s.logCfg.logger, req.Id)
	ctx = utils.WithFields(ctx, s.logCfg.getFields(writer, req))
	utils.CtxDebug(ctx, "extra: %s", req.Extra)

	var resp *dns.Msg
	var hitHosts, hitCache bool
	defer func() { // 返回响应
		if resp == nil {
			resp = &dns.Msg{}
		}
		s.logCfg.logFunc(req, hitHosts, hitCache)(ctx, "response: %s", resp.Answer)
		resp.SetReply(req)
		_ = writer.WriteMsg(resp)
		_ = writer.Close()
	}()

	if len(req.Question) == 0 {
		return
	}
	question := req.Question[0]
	if s.disableQTypes[question.Qtype] { // 判断是否阻止查询
		return
	}
	if resp = s.tryHosts(ctx, question); resp != nil { // 判断是否命中hosts
		hitHosts = true
		return
	}
	if resp = s.Cache.Get(req); resp != nil { // 判断是否命中缓存
		hitCache = true
		return
	}
	defer func() { s.Cache.Set(req, resp) }() // 将结果加入缓存

	for _, group := range s.groups {
		if match, ok := group.matcher.Match(question.Name); ok && match {
			resp = group.Handle(ctx, req, nil)
			break
		}
	}
}

// tryHosts 如DNS查询请求匹配hosts，则生成对应dns记录并返回。否则返回nil
func (s *DNSServer) tryHosts(ctx context.Context, question dns.Question) *dns.Msg {
	if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
		ipv6 := question.Qtype == dns.TypeAAAA
		for _, reader := range s.Hosts {
			record, hostname := "", question.Name
			if record = reader.Record(hostname, ipv6); record == "" {
				// 去掉末尾的根域名再找一次
				record = reader.Record(hostname[:len(hostname)-1], ipv6)
			}
			if record != "" {
				if ret, err := dns.NewRR(record); err != nil {
					utils.CtxError(ctx, fmt.Sprintf("make dns.RR for %q: %s", record, err))
				} else {
					r := new(dns.Msg)
					r.Answer = append(r.Answer, ret)
					return r
				}
			}
		}
	}
	return nil
}

// NewLogConfig 初始化一个请求日志配置
func NewLogConfig(closer io.WriteCloser, ignoreQTypes []string,
	ignoreHosts, ignoreCache bool) *LogConfig {
	logger := logrus.New()
	logger.SetLevel(logrus.StandardLogger().Level)
	if closer != nil {
		logger.SetOutput(closer)
	}
	qTypes := make(map[uint16]bool, len(ignoreQTypes))
	for _, qTypeStr := range ignoreQTypes {
		if qType, exists := dns.StringToType[strings.ToUpper(qTypeStr)]; exists {
			qTypes[qType] = true
		}
	}
	return &LogConfig{closer: closer, logger: logger, ignoreQTypes: qTypes,
		ignoreHosts: ignoreHosts, ignoreCache: ignoreCache}
}

// LogConfig DNSServer专用的请求日志配置
type LogConfig struct {
	closer       io.WriteCloser
	logger       *logrus.Logger
	ignoreQTypes map[uint16]bool
	ignoreHosts  bool
	ignoreCache  bool
}

func (l *LogConfig) getFields(writer dns.ResponseWriter, req *dns.Msg) logrus.Fields {
	fields := logrus.Fields{"SRC": writer.RemoteAddr().String()}
	for _, question := range req.Question {
		fields["QUESTION"] = question.Name
		fields["Q_TYPE"] = dns.Type(question.Qtype).String()
		break
	}
	return fields
}

func (l *LogConfig) logFunc(req *dns.Msg, hitHosts, hitCache bool,
) func(ctx context.Context, format string, args ...interface{}) {
	if hitHosts && l.ignoreHosts || hitCache && l.ignoreCache {
		return utils.CtxDebug
	}
	for _, question := range req.Question {
		if ignore, ok := l.ignoreQTypes[question.Qtype]; ok && ignore {
			return utils.CtxDebug
		}
	}
	return utils.CtxInfo
}

// Exit 关闭closer
func (l *LogConfig) Exit(ctx context.Context) {
	if l.closer != nil {
		if err := l.closer.Close(); err != nil {
			utils.CtxWarn(ctx, err.Error())
		}
	}
}
