package utils

import (
	"net"

	"github.com/miekg/dns"
)

type FakeRespWriter struct {
	Msg   *dns.Msg
	Bytes []byte
}

// NewFakeRespWriter 创建一个FakeRespWriter，用于手动请求dns.Handler时获取DNS响应
func NewFakeRespWriter() *FakeRespWriter {
	return &FakeRespWriter{}
}

func (w *FakeRespWriter) LocalAddr() net.Addr {
	return &net.IPAddr{IP: []byte{127, 0, 0, 1}}
}

func (w *FakeRespWriter) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: []byte{127, 0, 0, 1}}
}

func (w *FakeRespWriter) WriteMsg(msg *dns.Msg) error {
	w.Msg = msg
	return nil
}

func (w *FakeRespWriter) Write(bytes []byte) (int, error) {
	w.Bytes = bytes
	return len(bytes), nil
}

func (w *FakeRespWriter) Close() error {
	return nil
}

func (w *FakeRespWriter) TsigStatus() error {
	return nil
}

func (w *FakeRespWriter) TsigTimersOnly(bool) {
	return
}

func (w *FakeRespWriter) Hijack() {
	return
}
