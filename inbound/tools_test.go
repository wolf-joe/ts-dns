package inbound

import (
	"errors"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/core/utils"
	"github.com/wolf-joe/ts-dns/core/utils/mock"

	"net"
	"testing"
)

func TestAllInRange(t *testing.T) {
	resp := &dns.Msg{Answer: []dns.RR{&dns.A{A: net.IPv4(1, 1, 1, 1)}}}
	assert.False(t, allInRange(resp, cache.NewRamSetByText("")))
	assert.True(t, allInRange(resp, cache.NewRamSetByText("1.1.1.1")))
}

func TestFastestA(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	ctx := utils.NewCtx(nil, 0xffff)
	tcpPort := -1
	ch := make(chan *dns.Msg, 3)
	emptyMsg := &dns.Msg{}

	mocker := mock.Mocker{}
	defer mocker.Reset()
	mocker.Func(utils.PingIP, func(string, int, time.Duration) error {
		return errors.New("cannot ping now")
	})

	ch <- emptyMsg
	assert.Nil(t, fastestA(ctx, ch, 0, tcpPort))
	assert.Equal(t, emptyMsg, fastestA(ctx, ch, 1, tcpPort))

	ch <- &dns.Msg{Answer: []dns.RR{&dns.A{A: []byte{1, 1, 1, 1}}}}
	ch <- &dns.Msg{Answer: []dns.RR{&dns.A{A: []byte{1, 1, 1, 1}}}}
	assert.NotNil(t, fastestA(ctx, ch, 2, tcpPort))

	makeMsg := func() *dns.Msg {
		msg := &dns.Msg{}
		for i := byte(1); i < 255; i++ {
			msg.Answer = append(msg.Answer, &dns.A{A: []byte{1, 1, 1, i}})
		}
		return msg
	}
	msg := makeMsg()
	ch <- nil
	ch <- msg
	assert.Equal(t, msg, fastestA(ctx, ch, 2, tcpPort))

	mocker.Func(utils.PingIP, func(addr string, _ int, _ time.Duration) error {
		switch addr {
		case "1.1.1.10":
			return nil
		case "1.1.1.1", "1.1.1.2", "1.1.1.3":
			time.Sleep(50 * time.Millisecond)
			return nil
		default:
			return errors.New("timeout")
		}
	})
	ch <- nil
	ch <- makeMsg()
	ch <- nil
	msg = fastestA(ctx, ch, 3, tcpPort)
	assert.NotNil(t, msg)
	assert.Equal(t, 1, len(msg.Answer))
	assert.Equal(t, "1.1.1.10", msg.Answer[0].(*dns.A).A.String())

	time.Sleep(100 * time.Millisecond)
}
