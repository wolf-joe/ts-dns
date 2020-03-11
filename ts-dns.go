package main

import (
	"fmt"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

var dnsClient = new(dns.Client)

func queryDns(question dns.Question, server string,
	extra []dns.RR, dialer proxy.Dialer) (r *dns.Msg, err error) {
	msg := dns.Msg{}
	msg.Extra = extra
	msg.SetQuestion(question.Name, question.Qtype)

	var proxyConn net.Conn
	// 返回前缓存查询结果并关闭代理连接
	defer func() {
		setDNSCache(question, extra, r)
		if proxyConn != nil {
			_ = proxyConn.Close()
		}
	}()
	if dialer != nil {
		// 使用代理连接DNS服务器
		if proxyConn, err = dialer.Dial("tcp", server); err != nil {
			return nil, err
		} else {
			conn := &dns.Conn{Conn: proxyConn}
			if err = conn.WriteMsg(&msg); err != nil {
				return nil, err
			}
			return conn.ReadMsg()
		}
	} else {
		// 不使用代理
		r, _, err = dnsClient.Exchange(&msg, server)
		return r, err
	}
}

func isPolluted(domain string) (polluted bool, err error) {
	// 向clean组dns服务器（推荐设置为公共DNS）发送请求来判定域名是否被污染
	domain = "ne-" + strconv.FormatInt(time.Now().UnixNano(), 16) + "." + domain
	log.Println("[DEBUG] check pollute: " + domain)
	var r *dns.Msg
	for _, server := range config.Groups["clean"].DNS {
		question := dns.Question{Name: domain, Qtype: dns.TypeA}
		r, err = queryDns(question, server, []dns.RR{}, config.Groups["clean"].Dialer)
		if err != nil {
			log.Printf("[ERROR] query dns error: %v\n", err)
		}
		if r != nil {
			break
		}
	}
	// 对于很可能不存在的域名，如果直接返回一条A记录则判定为域名已被污染
	if r != nil && len(r.Answer) == 1 {
		switch r.Answer[0].(type) {
		case *dns.A:
			return true, nil
		}
	}
	return false, err
}

func getGroupName(domain string) (group string, reason string) {
	// 判断目标域名所在的分组
	// 优先检测预设规则
	for suffix, group := range suffixMap {
		if strings.HasSuffix(domain, suffix) {
			return group, "suffix " + suffix
		}
	}

	// 判断gfwlist
	if blocked, ok := config.GFWChecker.IsBlocked(domain); ok {
		if blocked {
			return "dirty", "GFWList"
		}
		return "clean", "GFWList"
	}

	// 从缓存中读取前次判断结果
	group = getGroupCache(domain)
	if _, ok := config.Groups[group]; ok {
		return group, "pollute cache" // 如果缓存内的groupName有效则直接返回
	}

	// 判断域名是否受到污染，并按污染结果将域名分组
	var setErr error
	defer func() {
		if setErr != nil {
			log.Printf("[ERROR] set group cache error: %s\n", setErr)
		}
	}()
	if polluted, err := isPolluted(domain); err != nil {
		log.Printf("[ERROR] check polluted error: %v\n", err)
		return "clean", "pollute detect err"
	} else if polluted {
		log.Printf("[WARNING] %s polluted\n", domain)
		setErr = setGroupCache(domain, "dirty")
		return "dirty", "pollute detect"
	} else {
		setErr = setGroupCache(domain, "clean")
		return "clean", "pollute detect"
	}
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
	if strings.Count(question.Name, ".ne-") > 1 {
		log.Fatalln("[CRITICAL] recursive query") // 防止递归
	}
	msg := fmt.Sprintf("[INFO] domain %s from %s ", question.Name, resp.RemoteAddr())
	// 判断域名是否存在于hosts内
	if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
		for _, reader := range hostsReaders {
			// hostname为domain去掉末尾"."符号后的值
			record, hostname := "", question.Name[:len(question.Name)-1]
			if record = reader.GenRecord(hostname, question.Qtype); record == "" {
				// 如hostname无对应的hosts记录，则用domain再找一次
				record = reader.GenRecord(question.Name, question.Qtype)
			}
			if record != "" {
				if ret, err := dns.NewRR(record); err != nil {
					log.Printf("[ERROR] make dns.RR error: %v\n", err)
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
	if r = getDNSCache(question, request.Extra); r != nil {
		log.Println(msg + "hit cache")
		return
	}

	var err error
	groupName, reason := getGroupName(question.Name)
	log.Println(msg + fmt.Sprintf("match group '%s' (%s)", groupName, reason))
	if group, ok := config.Groups[groupName]; ok {
		for _, server := range group.DNS { // 遍历DNS服务器
			r, err = queryDns(question, server, request.Extra, group.Dialer) // 发送查询请求
			if err != nil {
				log.Printf("[ERROR] query dns error: %v\n", err)
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
	initConfig()
	srv := &dns.Server{Addr: config.Listen, Net: "udp"}
	srv.Handler = &handler{}
	log.Printf("[WARNING] listen on %s/udp\n", config.Listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[CRITICAL] liten udp error: %v\n", err)
	}
}
