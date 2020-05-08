package main

import (
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/cmd/conf"
	"github.com/wolf-joe/ts-dns/inbound"
	"os"
	"time"
)

// VERSION 程序版本号
var VERSION = "dev"

func main() {
	// 读取命令行参数
	filename := flag.String("c", "ts-dns.toml", "config file path")
	reload := flag.Bool("r", false, "auto reload config file")
	showVer := flag.Bool("v", false, "show version and exit")
	debugMode := flag.Bool("vv", false, "show debug log")
	flag.Parse()
	if *showVer { // 显示版本号并退出
		fmt.Println(VERSION)
		os.Exit(0)
	}
	if *debugMode {
		log.SetLevel(log.DebugLevel)
		log.Debug("show debug log")
	}
	// 读取配置文件
	handler, err := conf.NewHandler(*filename)
	if err != nil {
		os.Exit(1)
	}
	if *reload { // 自动重载配置文件
		log.Warnf("auto reload " + *filename)
		go autoReload(handler, *filename)
	}
	// 启动dns服务后异步解析DoH服务器域名
	go func() { time.Sleep(time.Second); handler.ResolveDoH() }()
	// 启动dns服务
	srv := &dns.Server{Addr: handler.Listen, Net: handler.Network, Handler: handler}
	log.Warnf("listen on %s/%s", handler.Listen, handler.Network)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("listen faied: %v", err)
	}
}

// 持续监测目标配置文件，如文件发生变动则尝试载入，载入成功后更新现有handler的配置
func autoReload(handle *inbound.Handler, filename string) {
	fields := log.Fields{"file": filename}
	// 创建监测器
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.WithFields(fields).Errorf("create watcher error: %v", err)
		return
	}
	defer func() {
		_ = watcher.Close()
		log.WithFields(fields).Errorf("file watcher closed")
	}()
	// 指定监测文件
	if err = watcher.Add(filename); err != nil {
		log.WithFields(fields).Errorf("watch file error: %v", err)
		return
	}
	// 接收文件事件
	for {
		select {
		case event, ok := <-watcher.Events: // 出现文件事件
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write { // 文件变动事件
				log.WithFields(fields).Warnf("file changed, reloading")
				if newHandler, err := conf.NewHandler(filename); err == nil {
					newHandler.ResolveDoH()
					handle.Refresh(newHandler)
				}
			}
		case err, ok := <-watcher.Errors: // 出现错误
			if !ok {
				return
			}
			log.WithFields(fields).Errorf("watch error: %v", err)
		}
		time.Sleep(time.Second)
	}
}
