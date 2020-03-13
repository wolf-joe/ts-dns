package main

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/config"
	"log"
	"net"
)

var c *config.Config

// 列出dns响应中所有的ipv4地址
func extractIPv4(r *dns.Msg) (ips []string) {
	ips = []string{}
	if r == nil {
		return
	}
	for _, answer := range r.Answer {
		switch answer.(type) {
		case *dns.A:
			ips = append(ips, answer.(*dns.A).A.String())
		}
	}
	return
}

// 将dns响应中所有的ipv4地址加入目标group指定的ipset
func addIPSet(group config.Group, r *dns.Msg) (err error) {
	if group.IPSet == nil || r == nil {
		return
	}
	for _, ip := range extractIPv4(r) {
		err = group.IPSet.Add(ip, group.IPSetTTL)
	}
	return
}

// 依次向目标组内的dns服务器转发请求，获得响应则返回
func callDNS(group config.Group, request *dns.Msg) (r *dns.Msg) {
	var err error
	for _, caller := range group.Callers { // 遍历DNS服务器
		r, err = caller.Call(request) // 发送查询请求
		c.Cache.Set(request, r)
		if err != nil {
			log.Printf("[ERROR] query DNS error: %v\n", err)
		}
		if r != nil {
			return
		}
	}
	return nil
}

type handler struct{}

func (_ *handler) ServeDNS(resp dns.ResponseWriter, request *dns.Msg) {
	var r *dns.Msg
	var group config.Group
	defer func() {
		if r != nil { // 写入响应
			r.SetReply(request)
			_ = resp.WriteMsg(r)
			if err := addIPSet(group, r); err != nil { // 写入ipset
				log.Printf("[ERROR] add record to ipset error: %v\n", err)
			}
		}
		_ = resp.Close() // 结束连接
	}()

	question := request.Question[0]
	msg := fmt.Sprintf("[INFO] domain %s from %s ", question.Name, resp.RemoteAddr())
	// 判断域名是否存在于hosts内
	if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
		for _, reader := range c.HostsReaders {
			// hostname为domain去掉末尾"."符号后的值
			record, hostname := "", question.Name[:len(question.Name)-1]
			if record = reader.GenRecord(hostname, question.Qtype); record == "" {
				// 如hostname无对应的hosts记录，则用domain再找一次
				record = reader.GenRecord(question.Name, question.Qtype)
			}
			if record != "" {
				if ret, err := dns.NewRR(record); err != nil {
					log.Printf("[ERROR] make DNS.RR error: %v\n", err)
				} else {
					r = new(dns.Msg)
					r.Answer = append(r.Answer, ret)
				}
				log.Println(msg + "match hosts")
				return
			}
		}
	}

	// 检测dns缓存是否命中
	if r = c.Cache.Get(request); r != nil {
		log.Println(msg + "hit cache")
		return
	}

	// 判断域名是否匹配指定规则
	var name string
	for name, group = range c.GroupMap {
		if match, ok := group.Matcher.IsMatch(question.Name); ok && match {
			log.Println(msg + fmt.Sprintf("match group '%s' (rules)", name))
			r = callDNS(group, request)
			return
		}
	}

	// 先假设域名属于clean组
	group = c.GroupMap["clean"]
	r = callDNS(group, request)
	// 判断响应的ipv4中是否都为中国ip
	var allInCN = true
	for _, ip := range extractIPv4(r) {
		if !c.CNIPs.Contain(net.ParseIP(ip)) {
			allInCN = false
			break
		}
	}
	if allInCN {
		log.Println(msg + fmt.Sprintf("match group 'clean' (all ipv4 in CN)"))
	} else {
		// 出现非中国ip，根据gfwlist再次判断
		if blocked, ok := c.GFWChecker.IsBlocked(question.Name); ok && blocked {
			log.Println(msg + fmt.Sprintf("match group 'dirty' (GFWList)"))
			group = c.GroupMap["dirty"] // 判断域名属于dirty组
			r = callDNS(group, request)
		}
	}
}

func main() {
	c = initConfig()
	srv := &dns.Server{Addr: c.Listen, Net: "udp"}
	srv.Handler = &handler{}
	log.Printf("[WARNING] Listen on %s/udp\n", c.Listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[CRITICAL] liten udp error: %v\n", err)
	}
}
