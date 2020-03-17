package inbound

import (
	log "github.com/Sirupsen/logrus"
	"github.com/janeczku/go-ipset/ipset"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/outbound"
	"net"
	"sync"
)

type Group struct {
	Callers []outbound.Caller
	Matcher *matcher.ABPlus
	IPSet   *ipset.IPSet
}

type Handler struct {
	Mux          *sync.RWMutex
	Listen       string
	Cache        *cache.DNSCache
	GFWMatcher   *matcher.ABPlus
	CNIP         *cache.RamSet
	HostsReaders []hosts.Reader
	GroupMap     map[string]*Group
}

func (handler *Handler) ServeDNS(resp dns.ResponseWriter, request *dns.Msg) {
	handler.Mux.RLock() // 申请读锁，持续整个请求
	var r *dns.Msg
	var group *Group
	defer func() {
		if r != nil { // 写入响应
			r.SetReply(request)
			_ = resp.WriteMsg(r)
			if err := addIPSet(group, r); err != nil { // 写入ipset
				log.Errorf("add ipset error: %v", err)
			}
		}
		handler.Mux.RUnlock() // 读锁解除
		_ = resp.Close()      // 结束连接
	}()

	question := request.Question[0]
	fields := log.Fields{"domain": question.Name, "src": resp.RemoteAddr()}
	// 判断域名是否存在于hosts内
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
					log.Printf("[ERROR] make DNS.RR error: %v\n", err)
				} else {
					r = new(dns.Msg)
					r.Answer = append(r.Answer, ret)
				}
				log.WithFields(fields).Infof("hit hosts")
				return
			}
		}
	}

	// 检测dns缓存是否命中
	if r = handler.Cache.Get(request); r != nil {
		log.WithFields(fields).Infof("hit cache")
		return
	}

	// 判断域名是否匹配指定规则
	var name string
	for name, group = range handler.GroupMap {
		if match, ok := group.Matcher.Match(question.Name); ok && match {
			fields["group"] = name
			log.WithFields(fields).Infof("match by rules")
			r = callDNS(group, request)
			return
		}
	}

	// 先假设域名属于clean组
	group = handler.GroupMap["clean"]
	r = callDNS(group, request)
	// 判断响应的ipv4中是否都为中国ip
	var allInCN = true
	for _, ip := range extractIPv4(r) {
		if !handler.CNIP.Contain(net.ParseIP(ip)) {
			allInCN = false
			break
		}
	}
	if allInCN {
		fields["group"] = "clean"
		log.WithFields(fields).Infof("cn/empty ipv4")
	} else {
		// 出现非中国ip，根据gfwlist再次判断
		if blocked, ok := handler.GFWMatcher.Match(question.Name); ok && blocked {
			fields["group"] = "dirty"
			log.WithFields(fields).Infof("match gfwlist")
			group = handler.GroupMap["dirty"] // 判断域名属于dirty组
			r = callDNS(group, request)
		} else {
			fields["group"] = "clean"
			log.WithFields(fields).Infof("not match gfwlist")
		}
	}
	// 设置dns缓存
	handler.Cache.Set(request, r)
}

// 刷新配置，复制newHandler中除Mux、Listen之外的值
func (handler *Handler) Refresh(newHandler *Handler) {
	handler.Mux.Lock()
	defer handler.Mux.Unlock()

	if newHandler.Cache != nil {
		handler.Cache = newHandler.Cache
	}
	if newHandler.GFWMatcher != nil {
		handler.GFWMatcher = newHandler.GFWMatcher
	}
	if newHandler.CNIP != nil {
		handler.CNIP = newHandler.CNIP
	}
	if newHandler.HostsReaders != nil {
		handler.HostsReaders = newHandler.HostsReaders
	}
	if newHandler.GroupMap != nil {
		handler.GroupMap = newHandler.GroupMap
	}
}
