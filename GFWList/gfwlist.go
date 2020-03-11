package GFWList

import (
	"encoding/base64"
	"io/ioutil"
	"regexp"
	"strings"
)

type DomainChecker struct {
	isBlocked   map[string]bool
	blockedRegs []*regexp.Regexp
}

func (checker *DomainChecker) IsBlocked(domain string) (blocked bool, ok bool) {
	if domain == "" {
		return
	}
	// 域名末尾加上根域名
	if domain[len(domain)-1] != '.' {
		domain += "."
	}
	// 依次拆解域名进行匹配
	for suffix := domain; len(suffix) > 1; {
		if blocked, ok = checker.isBlocked[suffix]; ok {
			return // GFWList内有对应记录
		}
		suffix = suffix[strings.Index(suffix, ".")+1:] // 移除最低级的域名再次匹配
	}
	// 通配符匹配
	for _, regex := range checker.blockedRegs {
		if regex.MatchString(domain) {
			return true, true
		}
	}
	// 匹配失败
	return false, false
}

// 从GFWList规则中提取域名
func extractDomain(rule string) string {
	if i := strings.Index(rule, "||"); i != -1 {
		rule = rule[i+2:] // remove domain name anchor
	}
	if i := strings.Index(rule, "|"); i != -1 {
		rule = rule[i+1:] // remove address start anchor
	}
	if i := strings.Index(rule, "://"); i != -1 {
		rule = rule[i+3:] // remove method name
	}
	if i := strings.Index(rule, "/"); i != -1 {
		rule = rule[:i] // remove path of address
	}
	return rule
}

func NewCheckerByStr(text string, b64decode bool) (checker *DomainChecker, err error) {
	checker = &DomainChecker{isBlocked: map[string]bool{}}
	if b64decode { // base64解码
		if raw, err := base64.StdEncoding.DecodeString(text); err != nil {
			return nil, err
		} else {
			text = string(raw)
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if line == "" || line[0] == '!' || line[0] == '/' || line[0] == '[' {
			continue // 忽略空行、注释行、path规则、AutoProxy声明
		}
		line = strings.Replace(line, "%2F", "/", 1)
		domain := extractDomain(line)
		// 通过顶级域名判断域名是否有效
		var tld string
		if i := strings.LastIndex(domain, "."); i == -1 {
			continue // 无顶级域名
		} else {
			tld = domain[i+1:]
		}
		tldReg := regexp.MustCompile(`^[a-zA-Z]{2,}$`)
		idnReg := regexp.MustCompile(`^xn--[a-zA-Z0-9]{3,}$`)
		if !tldReg.MatchString(tld) && !idnReg.MatchString(tld) {
			continue // 无效
		}
		// 去掉域名前的"."号
		if domain[0] == '.' {
			domain = domain[1:]
		}
		// 域名末尾加上根域名"."
		if domain[len(domain)-1] != '.' {
			domain += "."
		}
		if strings.Index(domain, "*") != -1 {
			// 通配符表达式转正则表达式
			regex := strings.Replace(domain, ".", "\\.", -1)
			regex = strings.Replace(regex, "*", ".*", -1)
			regex = "^" + regex + "$"
			if line[:2] != "@@" {
				checker.blockedRegs = append(checker.blockedRegs, regexp.MustCompile(regex))
			}
		}
		checker.isBlocked[domain] = line[:2] != "@@"
	}
	return checker, nil
}

func NewCheckerByFn(filename string, b64decode bool) (checker *DomainChecker, err error) {
	if content, err := ioutil.ReadFile(filename); err != nil {
		return nil, err
	} else {
		return NewCheckerByStr(string(content), b64decode)
	}
}
