package cache

import (
	"sync"
	"time"
)

const (
	MinCleanTick = time.Second
)

type item struct {
	value  interface{}
	expire int64
}

type TTLMap struct {
	itemMap map[string]*item
	mux     *sync.RWMutex
}

func (m *TTLMap) Set(key string, value interface{}, ex time.Duration) {
	m.mux.Lock()
	defer m.mux.Unlock()
	m.itemMap[key] = &item{value: value, expire: time.Now().Add(ex).UnixNano()}
}

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

func (m TTLMap) Len() int {
	m.mux.RLock()
	defer m.mux.RUnlock()
	return len(m.itemMap)
}

func NewTTLMap(cleanTick time.Duration) (m *TTLMap) {
	if cleanTick < MinCleanTick {
		cleanTick = MinCleanTick
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
