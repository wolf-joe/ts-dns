package main

import (
	"flag"
	"github.com/go-redis/redis"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
	"gopkg.in/ini.v1"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

var serversMap = map[string][]string{
	"dirty": {},
	"clean": {},
}
var ruleMap = map[string]string{}
var s5Map = map[string]proxy.Dialer{}
var gfwList *GFWList

var listen = ":53"
var dnsClient = new(dns.Client)
var groupCache interface{}
var queryCache = new(TTLMap).Init(60)

func queryDns(question dns.Question, server string, s5dialer proxy.Dialer) (r *dns.Msg, err error) {
	// 查询缓存
	cacheKey := question.Name + strconv.FormatInt(int64(question.Qtype), 10)
	if cacheHit, ok := queryCache.Get(cacheKey); ok {
		log.Printf("[INFO] query cache hit\n")
		return cacheHit.(*dns.Msg), nil
	}
	msg := dns.Msg{}
	msg.SetQuestion(question.Name, question.Qtype)

	var s5co net.Conn
	// 返回前缓存查询结果并关闭socks5连接
	defer func() {
		queryCache.Set(cacheKey, r, time.Minute)
		if s5co != nil {
			_ = s5co.Close()
		}
	}()
	if s5dialer != nil {
		// 使用socks5代理连接DNS服务器
		if s5co, err = s5dialer.Dial("tcp", server); err != nil {
			return nil, err
		} else {
			co := &dns.Conn{Conn: s5co}
			if err = co.WriteMsg(&msg); err != nil {
				return nil, err
			}
			return co.ReadMsg()
		}
	} else {
		// 不使用socks5代理
		r, _, err = dnsClient.Exchange(&msg, server)
		return r, err
	}
}

func setGroupCache(domain string, group string) error {
	ex := time.Hour * 24
	switch groupCache.(type) {
	case *redis.Client:
		return groupCache.(*redis.Client).Set(domain, group, ex).Err()
	default:
		groupCache.(*TTLMap).Set(domain, group, ex)
		return nil
	}
}

func isPolluted(domain string) (polluted bool, err error) {
	// 向clean组dns服务器（推荐设置为公共DNS）发送请求来判定域名是否被污染
	domain = "ne-" + strconv.FormatInt(time.Now().UnixNano(), 16) + "." + domain
	log.Println("[DEBUG] check pollute: " + domain)
	var r *dns.Msg
	for _, server := range serversMap["clean"] {
		r, err = queryDns(dns.Question{Name: domain, Qtype: dns.TypeA}, server, s5Map["clean"])
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

func getGroupName(domain string) string {
	// 判断目标域名所在的分组
	// 优先检测预设规则
	for suffix, groupName := range ruleMap {
		if strings.HasSuffix(domain, suffix) {
			log.Printf("[INFO] %s match suffix %s\n", domain, suffix)
			return groupName
		}
	}

	// 判断gfwlist
	if groupName := gfwList.getGroupName(domain); groupName != "" {
		log.Printf("[INFO] %s match gfwlist\n", domain)
		return groupName
	}

	// 从缓存中读取前次判断结果
	var cacheHit interface{}
	switch groupCache.(type) {
	case *redis.Client:
		// get redis key时忽略错误，因为作者无法区分"key不存在"和其它错误
		cacheHit, _ = groupCache.(*redis.Client).Get(domain).Result()
	default:
		cacheHit, _ = groupCache.(*TTLMap).Get(domain)
	}
	if _, ok := serversMap[cacheHit.(string)]; ok {
		return cacheHit.(string) // 如果缓存内的groupName有效则直接返回
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
		return "clean"
	} else if polluted {
		log.Printf("[WARNING] %s polluted\n", domain)
		setErr = setGroupCache(domain, "dirty")
		return "dirty"
	} else {
		setErr = setGroupCache(domain, "clean")
		return "clean"
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
	log.Printf("[INFO] query %s from %s\n", question.Name, resp.RemoteAddr().String())
	var err error
	group := getGroupName(question.Name)
	for _, server := range serversMap[group] { // 遍历DNS服务器
		r, err = queryDns(question, server, s5Map[group]) // 发送查询请求
		if err != nil {
			log.Printf("[ERROR] query dns error: %v\n", err)
		}
		if r != nil {
			return
		}
	}
}

func main() {
	initConfig()
	srv := &dns.Server{Addr: listen, Net: "udp"}
	srv.Handler = &handler{}
	log.Printf("[WARNING] listen on %s/udp\n", listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[CITICAL] Failed to set udp listener %s\n", err.Error())
	}
}

func initConfig() {
	// 读取配置文件
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "ts-dns.ini", "Config File Path")
	flag.Parse()
	config, err := ini.Load(cfgPath)
	if err != nil {
		log.Fatalf("[CRITICAL] load config file error: %v\n", err)
	}
	// 监听地址
	mainSec := config.Section("main")
	if val := mainSec.Key("listen").String(); val != "" {
		listen = val // set global variable
	}
	// gfwlist
	if filename := mainSec.Key("gfwlist").String(); filename != "" {
		if gfwList, err = new(GFWList).Init(filename); err != nil {
			log.Fatalf("[CRITICAL] gfwlist read error: %v\n", err)
		}
	}
	// 服务器和规则列表
	svrSec := config.Section("servers")
	for groupName, svrStr := range svrSec.KeysHash() {
		serversMap[groupName] = strings.Split(svrStr, ",")
		for i, server := range serversMap[groupName] {
			server = strings.Trim(server, " ")
			if server != "" && !strings.ContainsAny(server, ":") {
				server += ":53"
			}
			serversMap[groupName][i] = server
		}
		// 读取rule:xxx下suffix对应的所有域名后缀
		ruleSec := config.Section("rule:" + groupName)
		suffixStr := ruleSec.Key("suffix").String()
		for _, suffix := range strings.Split(suffixStr, ",") {
			suffix = strings.Trim(suffix, " ")
			if suffix != "" {
				if suffix[len(suffix)-1] != '.' {
					suffix += "."
				}
				ruleMap[suffix] = groupName
			}
		}
		// 读取socks5代理地址
		s5addr := ruleSec.Key("socks5").String()
		if s5addr != "" {
			s5dialer, _ := proxy.SOCKS5("tcp", s5addr, nil, proxy.Direct)
			s5Map[groupName] = s5dialer
		}
	}
	// redis
	rdsSec := config.Section("redis")
	if rdsHost := rdsSec.Key("host").String(); rdsHost != "" {
		rdsPwd := rdsSec.Key("password").String()
		rdsDB, _ := strconv.Atoi(rdsSec.Key("db").String())
		groupCache = redis.NewClient(&redis.Options{Addr: rdsHost, Password: rdsPwd, DB: rdsDB})
		if _, err := groupCache.(*redis.Client).Ping().Result(); err != nil {
			log.Fatalf("[CRITICAL] redis connect error: %v\n", err)
		} else {
			log.Printf("[WARNING] connect redis://%s/%d success\n", rdsHost, rdsDB)
		}
	} else {
		groupCache = new(TTLMap).Init(60)
	}
	// 判断配置是否完整
	if len(serversMap["dirty"]) <= 0 || len(serversMap["clean"]) <= 0 {
		log.Fatalln("[CRITICAL] server of group dirty/clean cannot be empty")
	}
}
