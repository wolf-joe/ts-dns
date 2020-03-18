package inbound

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/cache"
	"net"
	"testing"
)

func TestTools(t *testing.T) {
	resp := &dns.Msg{Answer: []dns.RR{&dns.A{A: net.IPv4(1, 1, 1, 1)}}}
	assert.Equal(t, len(extractA(nil)), 0)
	assert.False(t, allInRange(resp, cache.NewRamSetByText("")))
	assert.True(t, allInRange(resp, cache.NewRamSetByText("1.1.1.1")))
}
