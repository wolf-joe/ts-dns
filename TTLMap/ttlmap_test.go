package TTLMap

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewTTLMap(t *testing.T) {
	ttlMap := NewMap(time.Second)
	ttlMap.Set("key1", "value1", time.Millisecond*500)
	ttlMap.Set("key2", "value2", time.Millisecond*500)
	val, ok := ttlMap.Get("key1")
	assert.Equal(t, val, "value1")
	assert.Equal(t, ok, true)

	time.Sleep(time.Millisecond * 600)
	val, ok = ttlMap.Get("key1")
	assert.Equal(t, val, nil)
	assert.Equal(t, ok, false)
	// key1在主动访问时被发现失效，从而删除，但key2仍然存在
	assert.Equal(t, ttlMap.Len(), 1)

	// key2被定时clean机制判断失效，从而删除
	time.Sleep(time.Millisecond * 500)
	assert.Equal(t, ttlMap.Len(), 0) //
}
