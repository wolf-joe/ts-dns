package inbound

import (
	"github.com/agiledragon/gomonkey"
	"github.com/miekg/dns"
	"github.com/sparrc/go-ping"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/mock"
	"net"
	"testing"
)

func TestTools(t *testing.T) {
	resp := &dns.Msg{Answer: []dns.RR{&dns.A{A: net.IPv4(1, 1, 1, 1)}}}
	assert.Equal(t, len(extractA(nil)), 0)
	assert.False(t, allInRange(resp, cache.NewRamSetByText("")))
	assert.True(t, allInRange(resp, cache.NewRamSetByText("1.1.1.1")))

	assert.True(t, pingRtt("") > MaxRtt)
	assert.True(t, pingRtt("111") > MaxRtt)
	mocker := mock.NewMocker()
	defer mocker.Reset()
	mocker.MethodSeq(&ping.Pinger{}, "Statistics", []gomonkey.Params{
		{&ping.Statistics{PacketsRecv: 1, AvgRtt: MaxRtt - 1}},
	})
	assert.True(t, pingRtt("1.1.1.1") < MaxRtt)
}
