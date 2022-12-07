package utils

import (
	"errors"
	"fmt"
	"github.com/wolf-joe/ts-dns/utils/mock"
	"net"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey"
	"github.com/sirupsen/logrus"
	"github.com/sparrc/go-ping"
	"github.com/stretchr/testify/assert"
)

func TestPingIP(t *testing.T) {
	// icmp ping
	assert.NotNil(t, PingIP("299.299.299.299", -1, time.Second))
	mocker := mock.Mocker{}
	defer mocker.Reset()
	mocker.MethodSeq(&ping.Pinger{}, "Statistics", []gomonkey.Params{
		{&ping.Statistics{PacketsRecv: 1, AvgRtt: 100}},
		{&ping.Statistics{PacketsRecv: 0, AvgRtt: 0}},
	})
	assert.Nil(t, PingIP("1.1.1.1", -1, time.Second))
	assert.NotNil(t, PingIP("1.1.1.1", -1, time.Second))

	// tcp ping
	mocker.FuncSeq(net.DialTimeout, []gomonkey.Params{
		{nil, fmt.Errorf("err")}, {&net.TCPConn{}, nil},
	})
	mocker.MethodSeq(&net.TCPConn{}, "Close", []gomonkey.Params{{nil}})
	assert.NotNil(t, PingIP("1.1.1.1", 80, time.Second))
	assert.Nil(t, PingIP("1.1.1.1", 80, time.Second))
}

func TestFastestPingIP(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	port, timeout := 80, 100*time.Millisecond

	mocker := mock.Mocker{}
	defer mocker.Reset()
	target := &net.TCPConn{}
	mocker.Method(target, "Close", func(*net.TCPConn) error { return nil })
	mocker.Func(net.DialTimeout, func(_, addr string, _ time.Duration) (net.Conn, error) {
		fmt.Println(addr)
		if addr == fmt.Sprintf("%s:%d", "1.1.1.1", port) {
			return &net.TCPConn{}, nil
		}
		time.Sleep(timeout)
		return nil, errors.New("timeout")
	})

	ip, _, err := FastestPingIP([]string{"1.1.1.1", "1.1.1.2"}, port, timeout)
	assert.Nil(t, err)
	assert.Equal(t, "1.1.1.1", ip)

	_, _, err = FastestPingIP([]string{"1.1.1.2", "1.1.1.3"}, port, timeout)
	assert.NotNil(t, err)
}
