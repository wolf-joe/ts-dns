package TTLMap

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

func (ttlMap *TTLMap) Set(key string, value interface{}, ex time.Duration) {
	ttlMap.mux.Lock()
	defer ttlMap.mux.Unlock()
	ttlMap.itemMap[key] = &item{value: value, expire: time.Now().Add(ex).UnixNano()}
}

func (ttlMap *TTLMap) Get(key string) (interface{}, bool) {
	ttlMap.mux.Lock()
	defer ttlMap.mux.Unlock()
	value, ok := ttlMap.itemMap[key]
	if !ok || time.Now().UnixNano() >= value.expire {
		delete(ttlMap.itemMap, key)
		return nil, false
	}
	return value.value, true
}

func (ttlMap TTLMap) Len() int {
	ttlMap.mux.RLock()
	defer ttlMap.mux.RUnlock()
	return len(ttlMap.itemMap)
}

func NewMap(cleanTick time.Duration) (m *TTLMap) {
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
