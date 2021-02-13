package common

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// ExtractA 提取dns响应中的A记录
func ExtractA(r *dns.Msg) (records []*dns.A) {
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

// ParseECS 将字符串（IP/CIDR）转换为EDNS CLIENT SUBNET对象
func ParseECS(s string) (ecs *dns.EDNS0_SUBNET, err error) {
	if s == "" {
		return nil, nil
	}
	if strings.Contains(s, "/") { // 解析网段
		ipAddr, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		mask, _ := ipNet.Mask.Size()
		ecs = &dns.EDNS0_SUBNET{Address: ipAddr, SourceNetmask: uint8(mask)}
	} else { // 解析ip
		addr, mask := net.ParseIP(s), uint8(0)
		if addr.To4() != nil {
			mask = uint8(net.IPv4len * 8)
		} else if addr.To16() != nil {
			mask = uint8(net.IPv6len * 8)
		} else {
			return nil, fmt.Errorf("wrong ip address: %s", s)
		}
		ecs = &dns.EDNS0_SUBNET{Address: addr, SourceNetmask: mask}
	}
	if ecs.Address.To4() != nil {
		ecs.Family = uint16(1)
	} else {
		ecs.Family = uint16(2)
	}
	return ecs, nil
}

// FormatECS 将DNS请求/响应里的EDNS CLIENT SUBNET对象格式化为字符串
func FormatECS(r *dns.Msg) string {
	if r == nil {
		return ""
	}
	for _, extra := range r.Extra {
		switch extra.(type) {
		case *dns.OPT:
			for _, opt := range extra.(*dns.OPT).Option {
				switch opt.(type) {
				case *dns.EDNS0_SUBNET:
					ecs := opt.(*dns.EDNS0_SUBNET)
					return fmt.Sprintf("%s/%d", ecs.Address, ecs.SourceNetmask)
				}
			}
		}
	}
	return ""
}

// SetDefaultECS 为DNS请求/响应设置默认的ECS对象
func SetDefaultECS(r *dns.Msg, ecs *dns.EDNS0_SUBNET) {
	if r == nil || ecs == nil {
		return
	}
	firstOPTIndex := -1
	for index, extra := range r.Extra {
		switch extra.(type) {
		case *dns.OPT:
			if firstOPTIndex < 0 {
				firstOPTIndex = index
			}
			for _, opt := range extra.(*dns.OPT).Option {
				switch opt.(type) {
				case *dns.EDNS0_SUBNET:
					return // 如已存在ECS对象则直接结束
				}
			}
		}
	}
	if firstOPTIndex < 0 {
		// 如果r.Extra为空或所有值都不为*dns.OPT，则在r.Extra的末尾添加一个*dns.OPT
		opt := &dns.OPT{Option: []dns.EDNS0{ecs}}
		opt.SetUDPSize(4096)
		opt.Hdr.Name, opt.Hdr.Rrtype = ".", dns.TypeOPT
		r.Extra = append(r.Extra, opt)
	} else {
		// 否则在第一个*dns.OPT的Option列表的开头插入ECS对象
		opt := r.Extra[firstOPTIndex].(*dns.OPT)
		opt.Option = append([]dns.EDNS0{ecs}, opt.Option...)
	}
}

// RemoveEDNSCookie 移除EDNS Cookie
func RemoveEDNSCookie(msg *dns.Msg) {
	if msg == nil {
		return
	}
	for _, extra := range msg.Extra {
		switch v := extra.(type) {
		case *dns.OPT:
			for i := 0; i < len(v.Option); i++ {
				switch v.Option[i].(type) {
				case *dns.EDNS0_COOKIE:
					v.Option = append(v.Option[:i], v.Option[i+1:]...)
					i--
				}
			}
		}
	}
}

// RemoveA 移除dns响应中的A记录
func RemoveA(resp *dns.Msg) {
	if resp == nil {
		return
	}
	for i := 0; i < len(resp.Answer); i++ {
		switch resp.Answer[i].(type) {
		case *dns.A:
			resp.Answer = append(resp.Answer[:i], resp.Answer[i+1:]...)
			i--
		}
	}
}
