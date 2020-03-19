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
	minReloadTick = time.Second // 当reloadTick低于该值时不自动重载hosts
)

// Reader Hosts读取器
type Reader interface {
	IP(hostname string, ipv6 bool) string
	Record(hostname string, ipv6 bool) string
}

// TextReader 基于文本的读取器
type TextReader struct {
	v4Map map[string]string
	v6Map map[string]string
}

// IP 获取hostname对应的ip地址，如不存在则返回空串
func (r *TextReader) IP(hostname string, ipv6 bool) (val string) {
	if ipv6 {
		val, _ = r.v6Map[hostname]
	} else {
		val, _ = r.v4Map[hostname]
	}
	return
}

// Record 生成hostname对应的dns记录，格式为"hostname ttl IN A ip"，如不存在则返回空串
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

// NewReaderByText 解析文本内容中的Hosts
func NewReaderByText(text string) (r *TextReader) {
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

// FileReader 基于文件的读取器
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
	if r.reloadTick < minReloadTick || time.Now().Before(r.timestamp.Add(r.reloadTick)) {
		return
	}
	// read host file again
	nr, err := NewReaderByFile(r.filename, r.reloadTick)
	// 当hosts文件读取失败时不更新内存中已有hosts记录
	if err == nil {
		r.reader = nr.reader
	}
	r.timestamp = time.Now()
}

// IP 获取hostname对应的ip地址，如不存在则返回空串
func (r *FileReader) IP(hostname string, ipv6 bool) string {
	r.reload()
	return r.reader.IP(hostname, ipv6)
}

// Record 生成hostname对应的dns记录，格式为"hostname ttl IN A ip"，如不存在则返回空串
func (r *FileReader) Record(hostname string, ipv6 bool) string {
	r.reload()
	return r.reader.Record(hostname, ipv6)
}

// NewReaderByFile 解析目标文件内容中的Hosts
func NewReaderByFile(filename string, reloadTick time.Duration) (r *FileReader, err error) {
	var raw []byte
	if raw, err = ioutil.ReadFile(filename); err != nil {
		return
	}
	r = &FileReader{mux: new(sync.Mutex), filename: filename, reloadTick: reloadTick}
	r.reader = NewReaderByText(string(raw))
	r.timestamp = time.Now()
	return
}
