package redirector

import (
	"bufio"
	"fmt"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/outbound"
	"github.com/yl2chen/cidranger"
	"net"
	"os"
	"strings"
)

const (
	TypeMatchCidr    = "match_cidr"
	TypeMisMatchCidr = "mismatch_cidr"
)

type Redirector func(src outbound.IGroup, req, resp *dns.Msg) outbound.IGroup

func NewRedirector(globalConf *config.Conf, groups map[string]outbound.IGroup) (Redirector, error) {
	// redirector name -> instance
	redirectorMap := make(map[string]iRedirector, len(globalConf.Redirectors))
	for name, conf := range globalConf.Redirectors {
		var err error
		switch strings.ToLower(conf.Type) {
		case TypeMatchCidr, TypeMisMatchCidr:
			redirectorMap[name], err = newCidrRedirector(name, conf, groups)
		default:
			err = fmt.Errorf("unknown type: %q", conf.Type)
		}
		if err != nil {
			return nil, fmt.Errorf("build redirector %q failed: %+v", name, err)
		}
	}
	// group name -> instance
	group2redir := make(map[string]iRedirector, len(globalConf.Groups))
	for name, conf := range globalConf.Groups {
		if conf.Redirector != "" {
			instance, exists := redirectorMap[conf.Redirector]
			if !exists {
				return nil, fmt.Errorf("redirector %q for group %q not exists", conf.Redirector, name)
			}
			group2redir[name] = instance
		}
	}
	// return runtime redirector
	var redirector Redirector
	redirector = func(src outbound.IGroup, req, resp *dns.Msg) outbound.IGroup {
		instance, exists := group2redir[src.Name()]
		if !exists {
			return nil
		}
		newGroup := instance.Redirect(req, resp)
		if src.Name() == newGroup.Name() {
			logrus.Warnf("redirector %q redirect to original group %q", instance, src)
			return nil
		}
		return newGroup
	}
	return redirector, nil
}

type iRedirector interface {
	Redirect(req, resp *dns.Msg) outbound.IGroup
	String() string
}

var (
	_ iRedirector = &cidrRedirector{}
)

type cidrRedirector struct {
	name   string
	ranger cidranger.Ranger
	notIn  bool // check is ip NOT in ranger
	dst    outbound.IGroup
}

func (r *cidrRedirector) Redirect(_, resp *dns.Msg) outbound.IGroup {
	match := func(ip net.IP) bool {
		isIn, err := r.ranger.Contains(ip)
		if err != nil {
			logrus.Debugf("check cidr contains %s in %s failed: %+v", ip, r, err)
			return false
		}
		if r.notIn {
			return !isIn
		}
		return isIn
	}
	for _, _rr := range resp.Answer {
		switch rr := _rr.(type) {
		case *dns.A:
			if match(rr.A) {
				return r.dst
			}
		case *dns.AAAA:
			if match(rr.AAAA) {
				return r.dst
			}
		}
	}
	return nil
}

func (r *cidrRedirector) String() string { return "cidr_redirector_" + r.name }

func newCidrRedirector(name string, conf config.RedirectorConf, groups map[string]outbound.IGroup) (*cidrRedirector, error) {
	// find dst group
	dst, exists := groups[conf.DstGroup]
	if !exists {
		return nil, fmt.Errorf("unkonwn dst group: %q", conf.DstGroup)
	}
	// build ranger
	ranger := cidranger.NewPCTrieRanger()
	addEntry := func(val string) error {
		_, ipNet, err := net.ParseCIDR(val)
		if err != nil {
			return fmt.Errorf("parse cidr %q failed: %w", val, err)
		}
		if err = ranger.Insert(cidranger.NewBasicRangerEntry(*ipNet)); err != nil {
			return fmt.Errorf("add cidr %q to ranger failed: %w", val, err)
		}
		return nil
	}
	// read cidr list
	for _, rule := range conf.Rules {
		if err := addEntry(rule); err != nil {
			return nil, err
		}
	}
	if conf.RulesFile != "" {
		logrus.Debugf("read rules file %q for redirector %s", name, conf.RulesFile)
		file, err := os.Open(conf.RulesFile)
		if err != nil {
			return nil, fmt.Errorf("open %q failed: %w", conf.RulesFile, err)
		}
		defer func() { _ = file.Close() }()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				continue
			}
			if err = addEntry(line); err != nil {
				return nil, err
			}
		}
		if err = scanner.Err(); err != nil {
			return nil, fmt.Errorf("scan %q failed: %w", conf.RulesFile, err)
		}
	}
	// return redirector
	redir := &cidrRedirector{
		name:   name,
		ranger: ranger,
		notIn:  false,
		dst:    dst,
	}
	if conf.Type == TypeMisMatchCidr {
		redir.notIn = true
	}
	return redir, nil
}
