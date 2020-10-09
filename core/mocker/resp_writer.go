package mocker

import (
	"net"

	"github.com/miekg/dns"
)

type FakeRespWriter struct {
}

func (w *FakeRespWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 999,
	}
}

func (w *FakeRespWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 999,
	}
}

func (w *FakeRespWriter) WriteMsg(msg *dns.Msg) error {
	panic("implement me")
}

func (w *FakeRespWriter) Write(bytes []byte) (int, error) {
	panic("implement me")
}

func (w *FakeRespWriter) Close() error {
	panic("implement me")
}

func (w *FakeRespWriter) TsigStatus() error {
	panic("implement me")
}

func (w *FakeRespWriter) TsigTimersOnly(b bool) {
	panic("implement me")
}

func (w *FakeRespWriter) Hijack() {
	panic("implement me")
}
