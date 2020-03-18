package inbound

import (
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/cache"
	"net"
)

// 提取dns响应中的A记录列表
func extractA(r *dns.Msg) (ips []string) {
	ips = []string{}
	if r == nil {
		return
	}
	for _, answer := range r.Answer {
		switch answer.(type) {
		case *dns.A:
			ips = append(ips, answer.(*dns.A).A.String())
		}
	}
	return
}

// 如dns响应中所有ipv4地址都在目标范围内（或没有ipv4地址）返回true，否则返回False
func allInRange(r *dns.Msg, ipRange *cache.RamSet) bool {
	for _, ip := range extractA(r) {
		if ipv4 := net.ParseIP(ip).To4(); ipv4 != nil && !ipRange.Contain(ipv4) {
			return false
		}
	}
	return true
}
