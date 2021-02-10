package inbound

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/core/common"
	"github.com/wolf-joe/ts-dns/core/utils"
)

const (
	pingTimeout = 500 * time.Millisecond
)

// 如dns响应中所有ipv4地址都在目标范围内（或没有ipv4地址）返回true，否则返回False
func allInRange(r *dns.Msg, ipRange *cache.RamSet) bool {
	for _, a := range common.ExtractA(r) {
		if ipv4 := net.ParseIP(a.A.String()).To4(); ipv4 != nil && !ipRange.Contain(ipv4) {
			return false
		}
	}
	return true
}

func fastestA(ctx context.Context, ch <-chan *dns.Msg, chLen int, tcpPort int) *dns.Msg {
	if chLen == 0 {
		return nil
	}
	const maxGoNum = 15 // 最大并发数量
	// 从msg ch中提取所有IPv4地址，并建立IPv4地址到msg的映射
	allIP := make([]string, 0, maxGoNum)
	msgMap := make(map[string]*dns.Msg, maxGoNum)
	var fastestMsg *dns.Msg // 最早抵达的msg，当测速失败时使用该响应返回
	for i := 0; i < chLen; i++ {
		msg := <-ch
		if fastestMsg == nil {
			fastestMsg = msg
		}
		for _, a := range common.ExtractA(msg) {
			ipV4 := a.A.String()
			if _, exists := msgMap[ipV4]; !exists {
				allIP = append(allIP, ipV4)
				msgMap[ipV4] = msg
				if len(msgMap) >= maxGoNum {
					goto doPing
				}
			}
		}
	}
doPing:
	switch len(msgMap) {
	case 0: // 没有任何IPv4地址
		return fastestMsg
	case 1: // 只有一个IPv4地址
		for _, msg := range msgMap {
			return msg
		}
	}
	// 并发测速
	begin := time.Now()
	pingDone := make(chan string, len(msgMap))
	for ipV4 := range msgMap {
		go func(addr string) {
			if err := utils.PingIP(addr, tcpPort, pingTimeout); err == nil {
				pingDone <- addr
			}
		}(ipV4)
	}
	var fastestIP string // 第一个从resCh返回的地址就是ping值最低的地址
	select {
	case fastestIP = <-pingDone:
	case <-time.After(pingTimeout):
	}
	cost := time.Now().Sub(begin).Milliseconds()
	utils.CtxDebug(ctx, "fastest ip of %s: %s(%dms)", allIP, fastestIP, cost)
	if msg, exists := msgMap[fastestIP]; exists && fastestIP != "" {
		// 删除msg内除fastestIP之外的其它A记录
		for i := 0; i < len(msg.Answer); i++ {
			if a, ok := msg.Answer[i].(*dns.A); ok && a.A.String() != fastestIP {
				msg.Answer = append(msg.Answer[:i], msg.Answer[i+1:]...)
				i--
			}
		}
		return msg
	}
	return fastestMsg
}
