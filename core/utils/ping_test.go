package utils

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey"
	"github.com/sparrc/go-ping"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/core/utils/mock"
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
