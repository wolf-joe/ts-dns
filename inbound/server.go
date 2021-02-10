package inbound

import (
	"context"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/janeczku/go-ipset/ipset"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/core/common"
	"github.com/wolf-joe/ts-dns/core/utils"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/outbound"
)

// Group 各域名组相关配置
type Group struct {
	Callers     []outbound.Caller
	Matcher     *matcher.ABPlus
	IPSet       *ipset.IPSet
	Concurrent  bool
	FastestV4   bool
	TCPPingPort int
	ECS         *dns.EDNS0_SUBNET
	NoCookie    bool
}

// CallDNS 向组内的dns服务器转发请求，可能返回nil
func (group *Group) CallDNS(ctx context.Context, request *dns.Msg) *dns.Msg {
	if len(group.Callers) == 0 || request == nil {
		return nil
	}
	request = request.Copy()
	common.SetDefaultECS(request, group.ECS)
	if group.NoCookie {
		common.RemoveEDNSCookie(request)
	}
	// 并发用的channel
	ch := make(chan *dns.Msg, len(group.Callers))
	// 包裹Caller.Call，方便实现并发
	call := func(caller outbound.Caller, request *dns.Msg) *dns.Msg {
		r, err := caller.Call(request)
		if err != nil {
			utils.CtxError(ctx, "query dns error: "+err.Error())
		}
		ch <- r
		return r
	}
	// 遍历DNS服务器
	for _, caller := range group.Callers {
		if group.Concurrent || group.FastestV4 {
			go call(caller, request)
		} else if r := call(caller, request); r != nil {
			return r
		}
	}
	// 并发情况下依次提取channel中的返回值
	if group.Concurrent && !group.FastestV4 {
		for i := 0; i < len(group.Callers); i++ {
			if r := <-ch; r != nil {
				return r
			}
		}
	} else if group.FastestV4 { // 选择ping值最低的IPv4地址作为返回值
		return fastestA(ctx, ch, len(group.Callers), group.TCPPingPort)
	}
	return nil
}

// AddIPSet 将dns响应中所有的ipv4地址加入group指定的ipset
func (group *Group) AddIPSet(ctx context.Context, r *dns.Msg) {
	if group.IPSet == nil || r == nil {
		return
	}
	for _, a := range common.ExtractA(r) {
		if err := group.IPSet.Add(a.A.String(), group.IPSet.Timeout); err != nil {
			utils.CtxError(ctx, "add ipset error: "+err.Error())
		}
	}
	return
}

// QueryLogger 打印请求日志的配置
type QueryLogger struct {
	logger       *log.Logger
	ignoreQTypes map[uint16]bool
	ignoreHosts  bool
	ignoreCache  bool
}

// ShouldIgnore 判断该次请求是否应该打印请求日志
func (logger *QueryLogger) ShouldIgnore(request *dns.Msg, hitHosts, hitCache bool) bool {
	if logger.logger.Level == log.DebugLevel {
		return false
	}
	if hitHosts && logger.ignoreHosts || hitCache && logger.ignoreCache {
		return true
	}
	for _, question := range request.Question {
		if ignore, ok := logger.ignoreQTypes[question.Qtype]; ok && ignore {
			return true
		}
	}
	return false
}

// GetFields 从dns请求中获取用于打印日志的fields
func (logger *QueryLogger) GetFields(writer dns.ResponseWriter, request *dns.Msg) log.Fields {
	fields := log.Fields{"SRC": writer.RemoteAddr().String()}
	for _, question := range request.Question {
		fields["QUESTION"] = question.Name
		fields["Q_TYPE"] = dns.Type(question.Qtype).String()
		break
	}
	return fields
}

// NewQueryLogger 创建一个QueryLogger
func NewQueryLogger(logger *log.Logger, ignoreQTypes []string,
	ignoreHosts, ignoreCache bool) *QueryLogger {
	queryLogger := &QueryLogger{
		logger: logger, ignoreHosts: ignoreHosts, ignoreCache: ignoreCache,
		ignoreQTypes: make(map[uint16]bool, len(ignoreQTypes)),
	}
	for _, qType := range ignoreQTypes {
		if t, ok := dns.StringToType[strings.ToUpper(qType)]; ok {
			queryLogger.ignoreQTypes[t] = true
		}
	}
	return queryLogger
}

// Handler 存储主要配置的dns请求处理器，程序核心
type Handler struct {
	Mux           *sync.RWMutex
	Listen        string
	Network       string
	DisableIPv6   bool
	Cache         *cache.DNSCache
	GFWMatcher    *matcher.ABPlus
	CNIP          *cache.RamSet
	HostsReaders  []hosts.Reader
	Groups        map[string]*Group
	QLogger       *QueryLogger
	DisableQTypes map[string]bool
}

// HitHosts 如dns请求匹配hosts，则生成对应dns记录并返回。否则返回nil
func (handler *Handler) HitHosts(ctx context.Context, request *dns.Msg) *dns.Msg {
	question := request.Question[0]
	if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
		ipv6 := question.Qtype == dns.TypeAAAA
		for _, reader := range handler.HostsReaders {
			record, hostname := "", question.Name
			if record = reader.Record(hostname, ipv6); record == "" {
				// 去掉末尾的根域名再找一次
				record = reader.Record(hostname[:len(hostname)-1], ipv6)
			}
			if record != "" {
				if ret, err := dns.NewRR(record); err != nil {
					utils.CtxError(ctx, "make DNS.RR error: "+err.Error())
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

// ServeDNS 处理dns请求，程序核心函数
func (handler *Handler) ServeDNS(writer dns.ResponseWriter, request *dns.Msg) {
	handler.Mux.RLock() // 申请读锁，持续整个请求
	ctx := utils.NewCtx(handler.QLogger.logger, request.Id)
	ctx = utils.WithFields(ctx, handler.QLogger.GetFields(writer, request))
	var r *dns.Msg
	var group *Group
	defer func() {
		if r == nil {
			r = &dns.Msg{}
		}
		r.SetReply(request) // 写入响应
		utils.CtxDebug(ctx, "response: %q", r.Answer)
		_ = writer.WriteMsg(r)
		if group != nil {
			group.AddIPSet(ctx, r) // 写入IPSet
		}
		handler.Mux.RUnlock() // 读锁解除
		_ = writer.Close()    // 结束连接
	}()

	question := request.Question[0]
	utils.CtxDebug(ctx, "question: %q, extra: %q", request.Question, request.Extra)
	if handler.DisableIPv6 && question.Qtype == dns.TypeAAAA {
		r = &dns.Msg{}
		return // 禁用IPv6时直接返回
	}
	if qType := dns.TypeToString[question.Qtype]; handler.DisableQTypes[qType] {
		r = &dns.Msg{}
		return // 禁用指定查询类型
	}
	// 检测是否命中hosts
	if r = handler.HitHosts(ctx, request); r != nil {
		if !handler.QLogger.ShouldIgnore(request, true, false) {
			utils.CtxInfo(ctx, "hit hosts")
		}
		return
	}
	// 检测是否命中dns缓存
	if r = handler.Cache.Get(request); r != nil {
		if !handler.QLogger.ShouldIgnore(request, false, true) {
			utils.CtxInfo(ctx, "hit cache")
		}
		return
	}

	// 判断域名是否匹配指定规则
	var name string
	for name, group = range handler.Groups {
		if match, ok := group.Matcher.Match(question.Name); ok && match {
			utils.CtxInfo(ctx, "match by rules, group: "+name)
			r = group.CallDNS(ctx, request)
			// 设置dns缓存
			handler.Cache.Set(request, r)
			return
		}
	}
	// 先用clean组dns解析
	group = handler.Groups["clean"] // 设置group变量以在defer里添加ipset
	r = group.CallDNS(ctx, request)
	if allInRange(r, handler.CNIP) {
		// 未出现非cn ip，流程结束
		utils.CtxInfo(ctx, "cn/empty ipv4, group: clean")
	} else if blocked, ok := handler.GFWMatcher.Match(question.Name); !ok || !blocked {
		// 出现非cn ip但域名不匹配gfwlist，流程结束
		utils.CtxInfo(ctx, "not match gfwlist, group: clean")
	} else {
		// 出现非cn ip且域名匹配gfwlist，用dirty组dns再次解析
		utils.CtxInfo(ctx, "match gfwlist, group: dirty")
		group = handler.Groups["dirty"] // 设置group变量以在defer里添加ipset
		r = group.CallDNS(ctx, request)
	}
	// 设置dns缓存
	handler.Cache.Set(request, r)
}

// Refresh 刷新配置，复制target中除Mux、Listen之外的值
func (handler *Handler) Refresh(target *Handler) {
	handler.Mux.Lock()
	defer handler.Mux.Unlock()

	if target.Cache != nil {
		handler.Cache = target.Cache
	}
	if target.GFWMatcher != nil {
		handler.GFWMatcher = target.GFWMatcher
	}
	if target.CNIP != nil {
		handler.CNIP = target.CNIP
	}
	if target.HostsReaders != nil {
		handler.HostsReaders = target.HostsReaders
	}
	if target.Groups != nil {
		for _, group := range target.Groups {
			for _, caller := range group.Callers {
				caller.Exit()
			}
		}
		handler.Groups = target.Groups
	}
	if target.QLogger != nil {
		handler.QLogger = target.QLogger
	}
	handler.DisableIPv6 = target.DisableIPv6
}

// IsValid 判断Handler是否符合运行条件
func (handler *Handler) IsValid() bool {
	if handler.Groups == nil {
		return false
	}
	clean, dirty := handler.Groups["clean"], handler.Groups["dirty"]
	if clean == nil || len(clean.Callers) <= 0 || dirty == nil || len(dirty.Callers) <= 0 {
		log.Errorf("dns of clean/dirty group cannot be empty")
		return false
	}
	return true
}
