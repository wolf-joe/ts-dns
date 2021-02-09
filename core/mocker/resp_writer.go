package mocker

import (
	"net"

	"github.com/miekg/dns"
)

type fakeRespWriter struct {
	Msg   *dns.Msg
	Bytes []byte
}

// NewFakeRespWriter 创建一个FakeRespWriter，用于手动请求dns.Handler时获取DNS响应
func NewFakeRespWriter() *fakeRespWriter {
	return &fakeRespWriter{}
}

func (w *fakeRespWriter) LocalAddr() net.Addr {
	return &net.IPAddr{IP: []byte{127, 0, 0, 1}}
}

func (w *fakeRespWriter) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: []byte{127, 0, 0, 1}}
}

func (w *fakeRespWriter) WriteMsg(msg *dns.Msg) error {
	w.Msg = msg
	return nil
}

func (w *fakeRespWriter) Write(bytes []byte) (int, error) {
	w.Bytes = bytes
	return len(bytes), nil
}

func (w *fakeRespWriter) Close() error {
	return nil
}

func (w *fakeRespWriter) TsigStatus() error {
	return nil
}

func (w *fakeRespWriter) TsigTimersOnly(bool) {
	return
}

func (w *fakeRespWriter) Hijack() {
	return
}
