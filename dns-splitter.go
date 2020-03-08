package main

import (
	"flag"
	"github.com/go-redis/redis"
	"github.com/miekg/dns"
	"gopkg.in/ini.v1"
	"log"
	"strconv"
	"strings"
	"time"
)

var listen, net = ":53", "udp"
var serversMap = map[string][]string{
	"dirty": {},
	"clean": {},
}
var ruleMap = map[string]string{}
var gfwList *GFWList

var dnsClient = new(dns.Client)
var groupCache interface{}

func queryDns(question dns.Question, servers []string) (*dns.Msg, error) {
	msg := dns.Msg{}
	msg.SetQuestion(question.Name, question.Qtype)
	var err error
	for _, server := range servers {
		if server == "" {
			continue
		}
		if r, _, _err := dnsClient.Exchange(&msg, server); r != nil {
			return r, nil
		} else if _err != nil {
			log.Printf("[ERROR] exchange error: %v\n", _err)
			err = _err
		}
	}
	return nil, err
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

func isPolluted(domain string) (bool, error) {
	// 向clean组dns服务器（推荐设置为公共DNS）发送请求来判定域名是否被污染
	domain = "ne-" + strconv.FormatInt(time.Now().UnixNano(), 16) + "." + domain
	log.Println("[DEBUG] check pollute: " + domain)
	r, err := queryDns(dns.Question{Name: domain, Qtype: dns.TypeA}, serversMap["clean"])
	if err != nil {
		return false, err
	}
	// 对于很可能不存在的域名，如果直接返回一条A记录则判定为域名已被污染
	if len(r.Answer) == 1 {
		switch r.Answer[0].(type) {
		case *dns.A:
			return true, nil
		}
	}
	return false, nil
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
	if polluted, err := isPolluted(domain); polluted {
		log.Printf("[WARNING] %s polluted\n", domain)
		if setErr := setGroupCache(domain, "dirty"); setErr != nil {
			log.Printf("[ERROR] set group cache error: %s\n", setErr)
		}
		return "dirty"
	} else if err == nil {
		if setErr := setGroupCache(domain, "clean"); setErr != nil {
			log.Printf("[ERROR] set group cache error: %s\n", setErr)
		}
	}
	return "clean"
}

type handler struct{}

func (_ *handler) ServeDNS(resp dns.ResponseWriter, request *dns.Msg) {
	question := request.Question[0]
	if strings.Count(question.Name, ".ne-") > 1 {
		log.Fatalln("[CRITICAL] recursive queryDns") // 防止递归
	}
	log.Printf("[INFO] query %s from %s\n", question.Name, resp.RemoteAddr().String())

	group := getGroupName(question.Name)
	if r, _ := queryDns(question, serversMap[group]); r != nil {
		r.SetReply(request)
		_ = resp.WriteMsg(r)
	}
	_ = resp.Close()
}

func main() {
	initConfig()
	srv := &dns.Server{Addr: listen, Net: net}
	srv.Handler = &handler{}
	log.Printf("[WARNING] listen on %s/%s\n", listen, net)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[CITICAL] Failed to set udp listener %s\n", err.Error())
	}
}

func initConfig() {
	// 读取配置文件
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "dns-splitter.ini", "Config File Path")
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
