package common

import (
	"github.com/agiledragon/gomonkey"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/cache"
	"testing"
	"time"
)

func TestMocker(t *testing.T) {
	mocker := Mocker{}

	ttlMap := cache.NewTTLMap(time.Hour)
	// 让ttlMap.Get返回非空
	mocker.MethodSeq(ttlMap, "Get", []gomonkey.Params{{"bbb", true}})
	// mock成功
	content, ok := ttlMap.Get("")
	assert.NotNil(t, content)
	assert.True(t, ok)
	// 修改FormatSubnet的返回值
	mocker.FuncSeq(FormatECS, []gomonkey.Params{{"1.1.1.1/32"}})
	// mock成功
	assert.Equal(t, FormatECS(nil), "1.1.1.1/32")
	// 取消所有mock
	assert.Equal(t, len(mocker.patches), 2)
	mocker.Reset()
	assert.Equal(t, len(mocker.patches), 0)
	// ttlMap.Get返回空
	content, ok = ttlMap.Get("")
	assert.Nil(t, content)
	assert.False(t, ok)
	// FormatSubnet的返回值被重置
	assert.NotEqual(t, FormatECS(nil), "1.1.1.1/32")
}
