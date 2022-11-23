package hosts

import (
	"bufio"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/config"
	"net"
	"os"
	"regexp"
	"strings"
	"unicode"
)

// region interface

type IDNSHosts interface {
	Get(req *dns.Msg) *dns.Msg
}

func NewDNSHosts(conf *config.Conf) (IDNSHosts, error) {
	domainMap := make(map[string]ipInfo, len(conf.Hosts))
	regexMap := make(map[*regexp.Regexp]ipInfo, len(conf.Hosts))
	load := func(host, ipStr string) error {
		ip := buildIPInfo(ipStr)
		if ip == zeroIP {
			return fmt.Errorf("parse %q to ip failed", ipStr)
		}
		if !strings.ContainsAny(host, "*?") {
			domainMap[host] = ip
			return nil
		}
		// wildcard to regexp
		host = strings.Replace(host, ".", "\\.", -1)
		host = strings.Replace(host, "*", ".*", -1)
		host = strings.Replace(host, "?", ".", -1)
		reg, err := regexp.Compile("^" + host + "$")
		if err != nil {
			return fmt.Errorf("build host regexp %q failed: %w", host, err)
		}
		regexMap[reg] = ip
		return nil
	}
	// parse hosts
	for host, ipStr := range conf.Hosts {
		if err := load(host, ipStr); err != nil {
			return nil, err
		}
	}
	// parse hosts files
	files := make([]*os.File, 0, len(conf.HostsFiles))
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	for _, filename := range conf.HostsFiles {
		logrus.Debugf("load hosts file %q", filename)
		file, err := os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("load hosts file %q error: %w", filename, err)
		}
		files = append(files, file)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			// parse each line
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				continue // ignore comment
			}
			parts := strings.FieldsFunc(line, unicode.IsSpace)
			if len(parts) < 2 {
				continue
			}
			if err = load(parts[0], parts[1]); err != nil {
				return nil, fmt.Errorf("load hosts file %q error: %w", filename, err)
			}
		}
	}
	return &HostReader{
		domainMap: domainMap,
		regexMap:  regexMap,
	}, nil
}

// endregion

// region impl
var (
	zeroIP           = ipInfo{}
	_      IDNSHosts = &HostReader{}
)

type ipInfo struct {
	val   string
	_type uint16
}

func (i ipInfo) Record(host string) string {
	if i._type == dns.TypeA {
		return host + " 0 IN A " + i.val
	}
	return host + " 0 IN AAAA " + i.val
}

func buildIPInfo(val string) ipInfo {
	ip := net.ParseIP(val)
	if ip.To4() != nil {
		return ipInfo{val: val, _type: dns.TypeA}
	} else if ip.To16() != nil {
		return ipInfo{val: val, _type: dns.TypeAAAA}
	}
	return zeroIP
}

// HostReader 管理hosts
type HostReader struct {
	domainMap map[string]ipInfo
	regexMap  map[*regexp.Regexp]ipInfo
}

func (h *HostReader) Get(req *dns.Msg) *dns.Msg {
	if len(req.Question) == 0 {
		return nil
	}
	host, qType := req.Question[0].Name, req.Question[0].Qtype
	if qType != dns.TypeA && qType != dns.TypeAAAA {
		return nil
	}

	getIP := func(host string) (ipInfo, bool) {
		if res, exists := h.domainMap[host]; exists {
			return res, true
		}
		for reg, res := range h.regexMap {
			if reg.MatchString(host) {
				return res, true
			}
		}
		return zeroIP, false
	}
	ip, exists := getIP(host)
	if !exists && strings.HasSuffix(host, ".") {
		ip, exists = getIP(host[:len(host)-1])
	}
	if !exists || ip._type != qType {
		return nil
	}
	rr, err := dns.NewRR(ip.Record(host))
	if err != nil {
		logrus.Errorf("build dns rr failed: %+v", err)
		return nil
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, rr)
	return resp
}

// endregion
