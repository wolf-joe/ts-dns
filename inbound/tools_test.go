package inbound

import (
	"fmt"
	"github.com/agiledragon/gomonkey"
	"github.com/miekg/dns"
	"github.com/sparrc/go-ping"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/core/mocker"
	"net"
	"testing"
)

func TestTools(t *testing.T) {
	resp := &dns.Msg{Answer: []dns.RR{&dns.A{A: net.IPv4(1, 1, 1, 1)}}}
	assert.False(t, allInRange(resp, cache.NewRamSetByText("")))
	assert.True(t, allInRange(resp, cache.NewRamSetByText("1.1.1.1")))

	assert.True(t, pingRtt("", -1) > maxRtt)
	assert.True(t, pingRtt("111", -1) > maxRtt)
	mocker := mocker.Mocker{}
	defer mocker.Reset()
	mocker.MethodSeq(&ping.Pinger{}, "Statistics", []gomonkey.Params{
		{&ping.Statistics{PacketsRecv: 1, AvgRtt: maxRtt - 1}},
	})
	assert.True(t, pingRtt("1.1.1.1", -1) < maxRtt)
	// 测试tcp ping
	mocker.FuncSeq(net.DialTimeout, []gomonkey.Params{
		{nil, fmt.Errorf("err")}, {&net.TCPConn{}, nil},
	})
	mocker.MethodSeq(&net.TCPConn{}, "Close", []gomonkey.Params{{nil}})
	assert.True(t, pingRtt("1.1.1.1", 80) > maxRtt)
	assert.True(t, pingRtt("1.1.1.1", 80) < maxRtt)
}

func TestTools_FastestA(t *testing.T) {
	// 预设ping rtt值
	gomonkey.ApplyFunc(pingRtt, func(ip string, _ int) int64 {
		if ip == "1.1.1.1" {
			return 100
		}
		return 200
	})

	chLen := 4
	ch := make(chan *dns.Msg, chLen)
	ch <- &dns.Msg{Answer: []dns.RR{&dns.A{A: net.IPv4(1, 1, 1, 1)}}}
	ch <- &dns.Msg{Answer: []dns.RR{&dns.A{A: net.IPv4(1, 1, 1, 2)}}}
	ch <- &dns.Msg{Answer: []dns.RR{&dns.A{A: net.IPv4(1, 1, 1, 2)}}}
	ch <- nil
	msg := fastestA(ch, chLen, -1)
	assert.NotNil(t, msg)
	assert.Equal(t, msg.Answer[0].(*dns.A).A.String(), "1.1.1.1")

	chLen = 0
	ch = make(chan *dns.Msg, chLen)
	msg = fastestA(ch, chLen, -1)
	assert.Nil(t, msg)

	chLen = 1
	ch = make(chan *dns.Msg, chLen)
	ch <- nil
	msg = fastestA(ch, chLen, -1)
	assert.Nil(t, msg)

	chLen = 1
	ch = make(chan *dns.Msg, chLen)
	ch <- &dns.Msg{Answer: []dns.RR{&dns.AAAA{}}}
	msg = fastestA(ch, chLen, -1)
	assert.NotNil(t, msg)
}
