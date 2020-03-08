package main

import (
	"encoding/base64"
	"io/ioutil"
	"strings"
)

type GFWList struct {
	dirtySuffix map[string]bool
	cleanSuffix map[string]bool
}

func (gfw *GFWList) Init(filename string) (*GFWList, error) {
	gfw.dirtySuffix = map[string]bool{}
	gfw.cleanSuffix = map[string]bool{}
	getSuffix := func(rule string) string {
		// 从adblock plus规则中提取域名后缀
		if i := strings.Index(rule, "||"); i != -1 {
			rule = rule[i+2:]
		}
		if i := strings.Index(rule, "|"); i != -1 {
			rule = rule[i+1:]
		}
		if i := strings.Index(rule, "://"); i != -1 {
			rule = rule[i+3:]
		}
		if i := strings.Index(rule, "/"); i != -1 {
			rule = rule[:i]
		}
		if i := strings.LastIndex(rule, "*"); i != -1 { // 对通配符做简单处理
			rule = rule[i+1:]
		} else if rule[0] != '.' {
			rule = "." + rule
		}
		return rule
	}
	if raw, err := ioutil.ReadFile(filename); err != nil {
		return nil, err
	} else if content, err := base64.StdEncoding.DecodeString(string(raw)); err != nil {
		return nil, err
	} else {
		// 解析gfwlist，不完全兼容adblock plus规则
		for _, line := range strings.Split(string(content), "\n") {
			var suffix string
			if line == "" || line[0] == '!' || line[0] == '/' || line[0] == '[' {
				continue
			} else {
				if suffix = getSuffix(line); suffix == "" {
					continue
				}
			}
			// 域名后加点方便匹配DNS请求
			suffix += "."
			if line[:2] == "@@" {
				if _, ok := gfw.cleanSuffix[suffix]; !ok {
					gfw.cleanSuffix[suffix] = true
				}
			} else {
				if _, ok := gfw.dirtySuffix[suffix]; !ok {
					gfw.dirtySuffix[suffix] = true
				}
			}
		}
	}
	return gfw, nil
}

func (gfw *GFWList) getGroupName(domain string) string {
	// 如域名在gfwlist名单内，返回dirty（域名被阻隔）/clean（域名未被阻隔），否则返回空串
	// 简单判断后缀，功能待完善
	if gfw == nil {
		return ""
	}
	domain = "." + domain
	for suffix := range gfw.dirtySuffix {
		//fmt.Printf("domain: %s, suffix: %s\n", domain, suffix)
		if strings.HasSuffix(domain, suffix) {
			return "dirty"
		}
	}
	for suffix := range gfw.cleanSuffix {
		//fmt.Printf("domain: %s, suffix: %s\n", domain, suffix)
		if strings.HasSuffix(domain, suffix) {
			return "clean"
		}
	}
	return ""
}
