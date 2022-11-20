package hosts

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/config"
	"net"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"unicode"
)

var (
	ErrUnknownQueryType = errors.New("unknown query type")
	ErrInvalidIP        = errors.New("invalid IP addr")
	zeroIP              = ipInfo{}
)

type ipInfo struct {
	val string
	dt  uint16
}

func (i ipInfo) Record(host string) string {
	if i.dt == dns.TypeA {
		return host + " 0 IN A " + i.val
	}
	return host + " 0 IN AAAA " + i.val
}

func buildIPInfo(val string) (ipInfo, error) {
	ip := net.ParseIP(val)
	if ip.To4() != nil {
		return ipInfo{val: val, dt: dns.TypeA}, nil
	} else if ip.To16() != nil {
		return ipInfo{val: val, dt: dns.TypeAAAA}, nil
	}
	return zeroIP, ErrInvalidIP
}

// HostReader 管理hosts
type HostReader struct {
	domainMap *atomic.Value // type: map[string]ipInfo
	regexMap  *atomic.Value // type: map[*regexp.Regexp]ipInfo
}

func (h *HostReader) getIP(host string) (ipInfo, bool) {
	if res, exists := h.domainMap.Load().(map[string]ipInfo)[host]; exists {
		return res, true
	}
	for reg, res := range h.regexMap.Load().(map[*regexp.Regexp]ipInfo) {
		if reg.MatchString(host) {
			return res, true
		}
	}
	return zeroIP, false
}

func (h *HostReader) Record(host string, query uint16) (dns.RR, error) {
	if query != dns.TypeA && query != dns.TypeAAAA {
		return nil, ErrUnknownQueryType
	}
	ip, exists := h.getIP(host)
	if !exists && strings.HasSuffix(host, ".") {
		ip, exists = h.getIP(host[:len(host)-1])
	}
	if !exists || ip.dt != query {
		return nil, nil
	}
	return dns.NewRR(ip.Record(host))
}

func (h *HostReader) ReloadConfig(conf *config.Conf) error {
	domainMap := make(map[string]ipInfo, len(conf.Hosts))
	regexMap := make(map[*regexp.Regexp]ipInfo, len(conf.Hosts))
	load := func(host, ipStr string) error {
		ip, err := buildIPInfo(ipStr)
		if err != nil {
			return fmt.Errorf("parse %q to host failed: %w", ipStr, err)
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
			return err
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
			return fmt.Errorf("load hosts file %q error: %w", filename, err)
		}
		files = append(files, file)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				continue
			}
			parts := strings.FieldsFunc(line, unicode.IsSpace)
			if len(parts) < 2 {
				continue
			}
			if err = load(parts[0], parts[1]); err != nil {
				return fmt.Errorf("load hosts file %q error: %w", filename, err)
			}
		}
	}
	// reload
	h.domainMap.Store(domainMap)
	h.regexMap.Store(regexMap)
	return nil
}

func NewHostReader(conf *config.Conf) (*HostReader, error) {
	r := &HostReader{
		domainMap: new(atomic.Value),
		regexMap:  new(atomic.Value),
	}
	if err := r.ReloadConfig(conf); err != nil {
		return nil, err
	}
	return r, nil
}
