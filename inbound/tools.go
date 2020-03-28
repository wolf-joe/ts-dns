package inbound

import (
	"github.com/miekg/dns"
	"github.com/sparrc/go-ping"
	"github.com/wolf-joe/ts-dns/cache"
	"math"
	"net"
	"sync"
	"time"
)

const MaxRtt = 500

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

// 获取到目标ip的ping值（毫秒）
func pingRtt(ip string) (rtt int64) {
	task, err := ping.NewPinger(ip)
	if err != nil {
		return MaxRtt + 1
	}
	task.Count, task.Timeout = 1, time.Millisecond*MaxRtt
	task.SetPrivileged(true)
	task.Run()
	stat := task.Statistics()
	if stat.PacketsRecv >= 1 {
		return stat.AvgRtt.Milliseconds()
	}
	return MaxRtt + 1
}

// 从dns msg chan中找出ping值最低的ipv4地址并将其所属的A记录打包返回
func fastestA(ch chan *dns.Msg, chLen int) (res *dns.Msg) {
	aLock, rttLock, wg := new(sync.Mutex), new(sync.Mutex), new(sync.WaitGroup)
	aMap, rttMap := map[string]*dns.A{}, map[string]int64{}
	for i := 0; i < chLen; i++ {
		msg := <-ch // 从chan中取出一个msg
		if msg != nil {
			res = msg // 防止被最后出现的nil覆盖
		}
		for _, a := range extractA(msg) {
			ipv4 := a.A.String()
			wg.Add(1)
			go func() {
				defer wg.Done()
				aLock.Lock()
				if _, ok := aMap[ipv4]; ok { // 防止重复ping
					aLock.Unlock()
					return
				}
				aMap[ipv4] = a
				aLock.Unlock()
				// 并发测速
				rtt := pingRtt(ipv4)
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
		if rtt < MaxRtt && rtt < lowestRtt {
			lowestRtt, fastestIP = rtt, ipv4
		}
	}
	// 用ping最小的ipv4地址覆盖msg
	if fastestIP != "" && res != nil {
		res.Answer = []dns.RR{aMap[fastestIP]}
	}
	return
}
