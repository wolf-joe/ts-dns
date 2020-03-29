package cache

import (
	"sync"
	"time"
)

const (
	minCleanTick = time.Second
)

type item struct {
	value  interface{}
	expire int64
}

// TTLMap 类似redis的超时map
type TTLMap struct {
	itemMap map[string]*item
	mux     *sync.RWMutex
}

// Set 放入一个指定有效期的对象
func (m *TTLMap) Set(key string, value interface{}, ex time.Duration) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.itemMap[key] = &item{value: value, expire: time.Now().Add(ex).UnixNano()}
}

// Get 取出对象，当后一个返回值为false时代表对象已过期或对象不存在
func (m *TTLMap) Get(key string) (interface{}, bool) {
	// get item, using read lock
	m.mux.RLock()
	value, ok := m.itemMap[key]
	m.mux.RUnlock()
	if !ok || time.Now().UnixNano() >= value.expire {
		// delete item, use write lock
		m.mux.Lock()
		delete(m.itemMap, key)
		m.mux.Unlock()
		return nil, false
	}
	return value.value, true
}

// Len 统计map中存在多少对象（包括已过期对象）
func (m TTLMap) Len() int {
	m.mux.RLock()
	defer m.mux.RUnlock()
	return len(m.itemMap)
}

// NewTTLMap 新建一个超时map，cleanTick为清除过期对象的频率
func NewTTLMap(cleanTick time.Duration) (m *TTLMap) {
	if cleanTick < minCleanTick {
		cleanTick = minCleanTick
	}
	m = &TTLMap{itemMap: map[string]*item{}, mux: new(sync.RWMutex)}
	go func() {
		for range time.Tick(cleanTick) {
			m.mux.Lock()
			for key, item := range m.itemMap {
				if time.Now().UnixNano() >= item.expire {
					delete(m.itemMap, key)
				}
			}
			m.mux.Unlock()
		}
	}()
	return
}
