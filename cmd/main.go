package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/core/model"
	"github.com/wolf-joe/ts-dns/core/utils"
	"github.com/wolf-joe/ts-dns/inbound"
)

// VERSION 程序版本号
var VERSION = "dev"

func main() {
	ctx := utils.NewCtx(nil, 0xffff)
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
	}
	// 读取配置文件
	handler, err := model.NewHandler(*filename)
	if err != nil {
		os.Exit(1)
	}
	if *reload { // 自动重载配置文件
		utils.CtxWarn(ctx, "auto reload "+*filename)
		go autoReload(ctx, handler, *filename)
	}
	// 启动dns服务，因为可能会同时监听TCP/UDP，所以封装个函数
	wg := sync.WaitGroup{}
	runSrv := func(net string) {
		defer wg.Done()
		srv := &dns.Server{Addr: handler.Listen, Net: net, Handler: handler}
		utils.CtxWarn(ctx, "listen on %s/%s", handler.Listen, net)
		if err := srv.ListenAndServe(); err != nil {
			utils.CtxError(ctx, err.Error())
		}
	}
	// 判断是否在配置文件里指定了监听协议
	if handler.Network != "" {
		wg.Add(1)
		go runSrv(handler.Network)
	} else {
		wg.Add(2)
		go runSrv("udp")
		go runSrv("tcp")
	}
	wg.Wait()
	utils.CtxInfo(ctx, "ts-dns exited.")
}

// 持续监测目标配置文件，如文件发生变动则尝试载入，载入成功后更新现有handler的配置
func autoReload(ctx context.Context, handle *inbound.Handler, filename string) {
	ctx = utils.WithFields(ctx, log.Fields{"file": filename})
	// 创建监测器
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		utils.CtxError(ctx, "create watcher error: "+err.Error())
		return
	}
	defer func() {
		_ = watcher.Close()
		utils.CtxError(ctx, "file watcher closed")
	}()
	// 指定监测文件
	if err = watcher.Add(filename); err != nil {
		utils.CtxError(ctx, "watch file error: "+err.Error())
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
				utils.CtxWarn(ctx, "file changed, reloading")
				if newHandler, err := model.NewHandler(filename); err == nil {
					handle.Refresh(newHandler)
				}
			}
		case err, ok := <-watcher.Errors: // 出现错误
			if !ok {
				return
			}
			utils.CtxError(ctx, "watch error: "+err.Error())
		}
		time.Sleep(time.Second)
	}
}
