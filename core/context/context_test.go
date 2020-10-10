package context

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/core/mocker"
)

func TestContext_Fields(t *testing.T) {
	ctx := NewEmptyContext(123)
	fields := ctx.Fields()
	assert.NotEmpty(t, fields[LocationKey])
	assert.Equal(t, "123", fields[LogIdKey])
}

func TestNewContext(t *testing.T) {
	writer := &mocker.FakeRespWriter{}
	request := &dns.Msg{Question: []dns.Question{{Name: "baidu.com.", Qtype: dns.TypeA}}}
	ctx := NewContext(writer, request)
	fields := ctx.Fields()
	assert.NotEmpty(t, fields[LocationKey])
	assert.NotEmpty(t, fields[LogIdKey])
	assert.NotEmpty(t, fields[QuestionKey])
	assert.NotEmpty(t, fields[QTypeKey])
	assert.NotEmpty(t, fields[SrcKey])
}

func TestConcurrent(t *testing.T) {
	ctx := NewEmptyContext(123)
	for i := 0; i < 10; i++ {
		go ctx.Fields()
	}
}
