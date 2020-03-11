package Hosts

import (
	"fmt"
	"github.com/miekg/dns"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"
)

type Reader interface {
	V4(hostname string) string
	V6(hostname string) string
	GenRecord(hostname string, t uint16) string
}

type TextReader struct {
	v4Map map[string]string
	v6Map map[string]string
}

func (r *TextReader) V4(hostname string) string {
	if val, ok := r.v4Map[hostname]; ok {
		return val
	}
	return ""
}
func (r *TextReader) V6(hostname string) string {
	if val, ok := r.v6Map[hostname]; ok {
		return val
	}
	return ""
}
func (r *TextReader) GenRecord(hostname string, t uint16) (record string) {
	if t == dns.TypeA {
		if ip := r.V4(hostname); ip != "" {
			return fmt.Sprintf("%s 0 IN A %s", hostname, ip)
		}
	} else if t == dns.TypeAAAA {
		if ip := r.V6(hostname); ip != "" {
			return fmt.Sprintf("%s 0 IN AAAA %s", hostname, ip)
		}
	}
	return ""
}
func NewTextReader(text string) (r *TextReader) {
	r = &TextReader{v4Map: map[string]string{}, v6Map: map[string]string{}}
	for _, line := range strings.Split(text, "\n") {
		line = strings.Trim(line, " \t\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		splitter := func(r rune) bool { return r == ' ' || r == '\t' }
		if arr := strings.FieldsFunc(line, splitter); len(arr) >= 2 {
			ip, hostname := net.ParseIP(arr[0]), arr[1]
			if ip.To4() != nil {
				r.v4Map[hostname] = ip.To4().String()
			} else if ip.To16() != nil {
				r.v6Map[hostname] = ip.To16().String()
			}
		}
	}
	return
}

type FileReader struct {
	mux       sync.Mutex
	filename  string
	timestamp time.Time
	timeout   time.Duration
	reader    *TextReader
}

func (r *FileReader) reload() {
	if time.Now().Before(r.timestamp.Add(r.timeout)) {
		return
	}
	// read host file again
	nr, _ := NewFileReader(r.filename, r.timeout)
	r.mux.Lock()
	r.reader, r.timestamp = nr.reader, nr.timestamp
	r.mux.Unlock()
}
func (r *FileReader) V4(hostname string) string {
	r.reload()
	return r.reader.V4(hostname)
}
func (r *FileReader) V6(hostname string) string {
	r.reload()
	return r.reader.V6(hostname)
}
func (r *FileReader) GenRecord(hostname string, t uint16) string {
	r.reload()
	return r.reader.GenRecord(hostname, t)
}
func NewFileReader(filename string, timeout time.Duration) (r *FileReader, err error) {
	var raw []byte
	if raw, err = ioutil.ReadFile(filename); err != nil {
		return
	}
	r = &FileReader{mux: sync.Mutex{}, filename: filename, timeout: timeout}
	r.reader = NewTextReader(string(raw))
	r.timestamp = time.Now()
	return
}
