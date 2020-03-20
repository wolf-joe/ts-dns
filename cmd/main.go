package main

import (
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"os"
)

// VERSION 程序版本号
var VERSION = "v0.9.0-dev"

func main() {
	// 读取命令行参数
	filename := flag.String("c", "ts-dns.toml", "config file path")
	reload := flag.Bool("r", false, "auto reload config file")
	showVer := flag.Bool("v", false, "show version and exit")
	flag.Parse()
	if *showVer { // 显示版本号并退出
		fmt.Println(VERSION)
		os.Exit(0)
	}
	// 读取配置文件
	handler, err := initHandler(*filename)
	if err != nil {
		os.Exit(1)
	}
	if *reload { // 自动重载配置文件
		log.Warnf("auto reload " + *filename)
		go autoReload(handler, *filename)
	}
	// 启动dns服务
	srv := &dns.Server{Addr: handler.Listen, Net: "udp", Handler: handler}
	log.Warnf("listen on %s/udp", handler.Listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listen udp error: %v", err)
	}
}
