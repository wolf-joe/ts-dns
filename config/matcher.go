package config

import (
	"io/ioutil"
	"net"
	"regexp"
	"strings"
)

// 解析ip地址/ip网段
type IPMatcher struct {
	subnet []*net.IPNet
	ipMap  map[string]bool
}

// 判断目标ip是否在范围内
func (matcher *IPMatcher) Contain(target net.IP) bool {
	if _, ok := matcher.ipMap[target.String()]; ok {
		return true
	}
	for _, subnet := range matcher.subnet {
		if subnet.Contains(target) {
			return true
		}
	}
	return false
}

func NewIPMatcherByText(text string) (matcher *IPMatcher) {
	matcher = &IPMatcher{subnet: []*net.IPNet{}, ipMap: map[string]bool{}}
	v4reg := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	cidr4reg := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$`)
	for _, line := range strings.Split(text, "\n") {
		line = strings.Trim(line, " \t\n\r")
		if v4reg.MatchString(line) {
			matcher.ipMap[net.ParseIP(line).String()] = true
		}
		if cidr4reg.MatchString(line) {
			if _, subnet, err := net.ParseCIDR(line); err == nil {
				matcher.subnet = append(matcher.subnet, subnet)
			}
		}
	}
	return matcher
}

func NewIPMatcherByFn(filename string) (matcher *IPMatcher, err error) {
	if raw, err := ioutil.ReadFile(filename); err != nil {
		return nil, err
	} else {
		return NewIPMatcherByText(string(raw)), nil
	}
}
