package TSDNS

import (
	"../DNSCaller"
	"../GFWList"
	"../Hosts"
	"../IPSet"
	"strings"
)

type Config struct {
	Listen       string
	GFWChecker   *GFWList.DomainChecker
	HostsReaders []Hosts.Reader
	GroupMap     map[string]Group
}

type Group struct {
	Callers  []DNSCaller.Caller
	Matcher  *DomainMatcher
	IPSet    *ipset.IPSet
	IPSetTTL int
}

type DomainMatcher struct {
	checker *GFWList.DomainChecker
}

func (matcher *DomainMatcher) IsMatch(domain string) (match bool, ok bool) {
	return matcher.checker.IsBlocked(domain)
}

func NewDomainMatcher(rules []string) (matcher *DomainMatcher) {
	matcher = new(DomainMatcher)
	text := strings.Join(rules, "\n")
	matcher.checker, _ = GFWList.NewCheckerByStr(text, false)
	return
}
