package inbound

import (
	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/sparrc/go-ping"
	"github.com/wolf-joe/ts-dns/cache"
	"math"
	"net"
	"strconv"
	"sync"
	"time"
)

const maxRtt = 500

// 提取dns响应中的A记录列表
func extractA(r *dns.Msg) (records []*dns.A) {
	if r == nil {
		return
	}
	for _, answer := range r.Answer {
		switch answer.(type) {
		case *dns.A:
			records = append(records, answer.(*dns.A))
		}
	}
	return
}

// 如dns响应中所有ipv4地址都在目标范围内（或没有ipv4地址）返回true，否则返回False
func allInRange(r *dns.Msg, ipRange *cache.RamSet) bool {
	for _, a := range extractA(r) {
		if ipv4 := net.ParseIP(a.A.String()).To4(); ipv4 != nil && !ipRange.Contain(ipv4) {
			return false
		}
	}
	return true
}

// 获取到目标ip的ping值（毫秒），当tcpPort大于0时使用tcp ping，否则使用icmp ping
func pingRtt(ip string, tcpPort int) (rtt int64) {
	if tcpPort > 0 { // 使用tcp ping
		begin, addr := time.Now(), ip+":"+strconv.Itoa(tcpPort)
		conn, err := net.DialTimeout("tcp", addr, time.Millisecond*maxRtt)
		if err != nil {
			return maxRtt + 1
		}
		defer func() { _ = conn.Close() }()
		rtt = time.Now().Sub(begin).Milliseconds()
		return rtt
	}
	// 使用icmp ping
	task, err := ping.NewPinger(ip)
	if err != nil {
		return maxRtt + 1
	}
	task.Count, task.Timeout = 1, time.Millisecond*maxRtt
	task.SetPrivileged(true)
	task.Run()
	stat := task.Statistics()
	if stat.PacketsRecv >= 1 {
		return stat.AvgRtt.Milliseconds()
	}
	return maxRtt + 1
}

// 从dns msg chan中找出ping值最低的ipv4地址并将其所属的A记录打包返回
func fastestA(ch chan *dns.Msg, chLen int, tcpPort int) (res *dns.Msg) {
	aLock, rttLock, wg := new(sync.Mutex), new(sync.Mutex), new(sync.WaitGroup)
	aMap, rttMap := map[string]dns.A{}, map[string]int64{}
	for i := 0; i < chLen; i++ {
		msg := <-ch // 从chan中取出一个msg
		if msg != nil {
			res = msg // 防止被最后出现的nil覆盖
		}
		for _, a := range extractA(msg) {
			ipv4, aObj := a.A.String(), *a // 用aObj实体变量来防止aMap的键值不一致
			wg.Add(1)
			go func() {
				defer wg.Done()
				aLock.Lock()
				if _, ok := aMap[ipv4]; ok { // 防止重复ping
					aLock.Unlock()
					return
				}
				aMap[ipv4] = aObj
				aLock.Unlock()
				// 并发测速
				rtt := pingRtt(ipv4, tcpPort)
				rttLock.Lock()
				rttMap[ipv4] = rtt
				rttLock.Unlock()
			}()
		}
	}
	wg.Wait()
	// 查找ping最小的ipv4地址
	lowestRtt, fastestIP := int64(math.MaxInt64), ""
	for ipv4, rtt := range rttMap {
		if rtt < maxRtt && rtt < lowestRtt {
			lowestRtt, fastestIP = rtt, ipv4
		}
	}
	// 用ping最小的ipv4地址覆盖msg
	if aObj := aMap[fastestIP]; fastestIP != "" && res != nil {
		res.Answer = []dns.RR{&aObj}
	} else {
		log.Error("find fastest ipv4 failed")
	}
	return
}
