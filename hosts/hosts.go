package hosts

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	MinReloadTick = time.Second
)

type Reader interface {
	IP(hostname string, ipv6 bool) string
	Record(hostname string, ipv6 bool) string
}

type TextReader struct {
	v4Map map[string]string
	v6Map map[string]string
}

// 获取hostname对应的ip地址，如不存在则返回空串
func (r *TextReader) IP(hostname string, ipv6 bool) (val string) {
	if ipv6 {
		val, _ = r.v6Map[hostname]
	} else {
		val, _ = r.v4Map[hostname]
	}
	return
}

// 生成hostname对应的dns记录，格式为"hostname ttl IN A ip"，如不存在则返回空串
func (r *TextReader) Record(hostname string, ipv6 bool) (record string) {
	ip, t := r.IP(hostname, ipv6), "A"
	if ipv6 {
		t = "AAAA"
	}
	if ip == "" {
		return ""
	}
	return fmt.Sprintf("%s 0 IN %s %s", hostname, t, ip)
}

// 解析文本内容中的Hosts
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
	mux        *sync.Mutex
	filename   string
	timestamp  time.Time
	reloadTick time.Duration
	reader     *TextReader
}

func (r *FileReader) reload() {
	r.mux.Lock()
	defer r.mux.Unlock()
	if r.reloadTick <= 0 || time.Now().Before(r.timestamp.Add(r.reloadTick)) {
		return
	}
	// read host file again
	nr, err := NewFileReader(r.filename, r.reloadTick)
	// 当hosts文件读取失败时不更新内存中已有hosts记录
	if err == nil {
		r.reader = nr.reader
	}
	r.timestamp = time.Now()
}

// 获取hostname对应的ip地址，如不存在则返回空串
func (r *FileReader) IP(hostname string, ipv6 bool) string {
	r.reload()
	return r.reader.IP(hostname, ipv6)
}

// 生成hostname对应的dns记录，格式为"hostname ttl IN A ip"，如不存在则返回空串
func (r *FileReader) Record(hostname string, ipv6 bool) string {
	r.reload()
	return r.reader.Record(hostname, ipv6)
}

// 解析目标文件内容中的Hosts
func NewFileReader(filename string, reloadTick time.Duration) (r *FileReader, err error) {
	if reloadTick < MinReloadTick {
		reloadTick = MinReloadTick
	}
	var raw []byte
	if raw, err = ioutil.ReadFile(filename); err != nil {
		return
	}
	r = &FileReader{mux: new(sync.Mutex), filename: filename, reloadTick: reloadTick}
	r.reader = NewTextReader(string(raw))
	r.timestamp = time.Now()
	return
}
