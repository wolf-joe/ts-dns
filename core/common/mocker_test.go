package common

import (
	"github.com/agiledragon/gomonkey"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMocker(t *testing.T) {
	mocker := Mocker{}

	msg := &dns.Msg{}
	// 修改msg.String()的返回值
	mocker.MethodSeq(msg, "String", []gomonkey.Params{{"test string"}})
	// mock成功
	assert.Equal(t, msg.String(), "test string")
	// 修改FormatSubnet的返回值
	mocker.FuncSeq(FormatECS, []gomonkey.Params{{"1.1.1.1/32"}})
	// mock成功
	assert.Equal(t, FormatECS(nil), "1.1.1.1/32")
	// 取消所有mock
	assert.Equal(t, len(mocker.patches), 2)
	mocker.Reset()
	assert.Equal(t, len(mocker.patches), 0)
	// msg.String()的返回值被重置
	assert.NotEqual(t, msg.String(), "test string")
	// FormatSubnet的返回值被重置
	assert.NotEqual(t, FormatECS(nil), "1.1.1.1/32")
}
