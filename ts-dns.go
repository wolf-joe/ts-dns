package main

import (
	"./TSDNS"
	"fmt"
	"github.com/miekg/dns"
	"log"
)

var config *TSDNS.Config

func getGroupName(domain string) (group string, reason string) {
	// 优先检测预设规则
	for name, group := range config.GroupMap {
		if match, ok := group.Matcher.IsMatch(domain); ok && match {
			return name, "rule"
		}
	}

	// 判断gfwlist
	if blocked, ok := config.GFWChecker.IsBlocked(domain); ok {
		if blocked {
			return "dirty", "GFWList"
		}
		return "clean", "GFWList"
	}
	return "clean", "default"
}

type handler struct{}

func (_ *handler) ServeDNS(resp dns.ResponseWriter, request *dns.Msg) {
	var r *dns.Msg
	defer func() {
		if r != nil {
			r.SetReply(request)
			_ = resp.WriteMsg(r)
		}
		_ = resp.Close()
	}()

	question := request.Question[0]
	msg := fmt.Sprintf("[INFO] domain %s from %s ", question.Name, resp.RemoteAddr())
	// 判断域名是否存在于hosts内
	if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
		for _, reader := range config.HostsReaders {
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
	if r = config.Cache.Get(request); r != nil {
		log.Println(msg + "hit cache")
		return
	}

	var err error
	name, reason := getGroupName(question.Name)
	log.Println(msg + fmt.Sprintf("match group '%s' (%s)", name, reason))
	if group, ok := config.GroupMap[name]; ok {
		for _, caller := range group.Callers { // 遍历DNS服务器
			r, err = caller.Call(request) // 发送查询请求
			config.Cache.Set(request, r)
			if err != nil {
				log.Printf("[ERROR] query DNS error: %v\n", err)
			}
			if r != nil {
				break
			}
		}
		// 将查询到的ip写入对应IPSet
		if group.IPSet != nil {
			for _, answer := range r.Answer {
				switch answer.(type) {
				case *dns.A:
					ip := answer.(*dns.A).A.String()
					if err = group.IPSet.Add(ip, group.IPSetTTL); err != nil {
						log.Printf("[ERROR] add %s to IPSet error: %v\n", ip, err)
					}
				}
			}
		}
	}
}

func main() {
	config = initConfig()
	srv := &dns.Server{Addr: config.Listen, Net: "udp"}
	srv.Handler = &handler{}
	log.Printf("[WARNING] Listen on %s/udp\n", config.Listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[CRITICAL] liten udp error: %v\n", err)
	}
}
