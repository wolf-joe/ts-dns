package inbound

import (
	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
)

func extractIPv4(r *dns.Msg) (ips []string) {
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

// 将dns响应中所有的ipv4地址加入目标group指定的ipset
func addIPSet(group *Group, r *dns.Msg) (err error) {
	if group == nil || group.IPSet == nil || r == nil {
		return
	}
	for _, ip := range extractIPv4(r) {
		err = group.IPSet.Add(ip, group.IPSetTTL)
	}
	return
}

// 依次向目标组内的dns服务器转发请求，获得响应则返回
func callDNS(group *Group, request *dns.Msg) (r *dns.Msg) {
	var err error
	for _, caller := range group.Callers { // 遍历DNS服务器
		r, err = caller.Call(request) // 发送查询请求
		if err != nil {
			log.Errorf("query dns error: %v", err)
		}
		if r != nil {
			return
		}
	}
	return nil
}
