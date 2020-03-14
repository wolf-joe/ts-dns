package config

import (
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/ipset"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/outbound"
)

type Config struct {
	Cache        *cache.DNSCache
	Listen       string
	GFWMatcher   *matcher.ABPlus
	CNIPs        *ipset.RamSet
	HostsReaders []hosts.Reader
	GroupMap     map[string]Group
}

type Group struct {
	Callers  []outbound.Caller
	Matcher  *matcher.ABPlus
	IPSet    *ipset.IPSet
	IPSetTTL int
}
