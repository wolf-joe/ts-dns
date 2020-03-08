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

var dnsClient = new(dns.Client)
var groupCache interface{}

func query(question dns.Question, servers []string) (*dns.Msg, error) {
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

func setGroup(name string, group string) error {
	ex := time.Hour * 24
	switch groupCache.(type) {
	case *redis.Client:
		return groupCache.(*redis.Client).Set(name, group, ex).Err()
	default:
		groupCache.(*TTLMap).Set(name, group, ex)
		return nil
	}
}

func isPolluted(name string) (bool, error) {
	// 判断域名是否被污染
	// 检测缓存是否命中
	var cacheHit interface{}
	switch groupCache.(type) {
	case *redis.Client:
		cacheHit, _ = groupCache.(*redis.Client).Get(name).Result()
	default:
		cacheHit, _ = groupCache.(*TTLMap).Get(name)
	}
	if cacheHit == "dirty" {
		return true, nil
	} else if cacheHit == "clean" {
		return false, nil
	}
	// 缓存未命中
	name = "ne-" + strconv.FormatInt(time.Now().UnixNano(), 16) + "." + name
	log.Println("[DEBUG] check pollute: " + name)
	r, err := query(dns.Question{Name: name, Qtype: dns.TypeA}, serversMap["risk"])
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
	if strings.Count(question.Name, "ne-") > 1 {
		log.Fatalln("[CRITICAL] recursive query") // 防止递归
	}
	log.Printf("[INFO] query %s from %s\n", question.Name, resp.RemoteAddr().String())

	// 优先检测预设规则
	for suffix, groupName := range ruleMap {
		if strings.HasSuffix(question.Name, suffix) {
			log.Printf("[INFO] match suffix %s\n", suffix)
			r, _ = query(question, serversMap[groupName])
			return
		}
	}
	// 判断域名是否被污染
	var setErr error
	if polluted, err := isPolluted(question.Name); polluted {
		log.Printf("[WARNING] polluted: %s\n", question.Name)
		setErr = setGroup(question.Name, "dirty")
		r, _ = query(question, serversMap["safe"])
		return
	} else if err == nil {
		setErr = setGroup(question.Name, "clean")
	}
	if setErr != nil {
		log.Printf("[ERROR] group set error: %s\n", setErr)
	}
	r, _ = query(question, serversMap["clean"])
	return
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
	//if filename := mainSec.Key("gfwlist").String(); filename != "" {
	//	var raw, content []byte
	//	if raw, err = ioutil.ReadFile(filename); err != nil {
	//		log.Fatalf("[CRITICAL] gfwlist read error: %v\n", err)
	//	}
	//	if content, err = base64.StdEncoding.DecodeString(string(raw)); err != nil {
	//		log.Fatalf("[CRITICAL] gfwlist decode error: %v\n", err)
	//	}
	//	lines := strings.Split(string(content), "\n")
	//	if gfwList, err = adblock.NewRules(lines, nil); err != nil {
	//		log.Fatalf("[CRITICAL] gfwlist parse error: %v\n", err)
	//	}
	//}
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
