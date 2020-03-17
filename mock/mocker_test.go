package mock

import (
	"github.com/agiledragon/gomonkey"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/cache"
	"testing"
	"time"
)

func falseFunc() bool {
	return false
}

func TestMocker(t *testing.T) {
	mocker := NewMocker()

	ttlMap := cache.NewTTLMap(time.Hour)
	// 让ttlMap.Get返回非空
	mocker.MethodSeq(ttlMap, "Get", []gomonkey.Params{{"bbb", true}})
	// mock成功
	content, ok := ttlMap.Get("")
	assert.NotNil(t, content)
	assert.True(t, ok)
	// 让falseFunc返回true
	mocker.FuncSeq(falseFunc, []gomonkey.Params{{true}})
	// mock成功
	assert.True(t, falseFunc())
	// 取消所有mock
	assert.Equal(t, len(mocker.patches), 2)
	mocker.Reset()
	assert.Equal(t, len(mocker.patches), 0)
	// ttlMap.Get返回空
	content, ok = ttlMap.Get("")
	assert.Nil(t, content)
	assert.False(t, ok)
	// falseFunc返回false
	assert.False(t, falseFunc())
}
