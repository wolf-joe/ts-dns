package inbound

import (
	"github.com/miekg/dns"
	"github.com/sparrc/go-ping"
	"github.com/wolf-joe/ts-dns/cache"
	"net"
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
