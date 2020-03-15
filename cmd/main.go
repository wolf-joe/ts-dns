package main

import (
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"os"
)

var VERSION = "unknown"

func main() {
	// 读取命令行参数
	filename := flag.String("c", "ts-dns.toml", "config file path")
	showVer := flag.Bool("v", false, "show version and exit")
	flag.Parse()
	if *showVer { // 显示版本号并退出
		fmt.Println(VERSION)
		os.Exit(0)
	}
	// 读取配置文件
	handler := initHandler(*filename)
	// 启动dns服务
	srv := &dns.Server{Addr: handler.Listen, Net: "udp", Handler: handler}
	log.Warnf("listen on %s/udp", handler.Listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listen udp error: %v", err)
	}
}
