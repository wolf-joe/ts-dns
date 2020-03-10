package TTLMap

import (
	"sync"
	"time"
)

type item struct {
	value  interface{}
	expire int64
}

type TTLMap struct {
	itemMap map[string]*item
	lock    sync.Mutex
}

func (ttlMap *TTLMap) Init(cycleSec int64) *TTLMap {
	ttlMap.lock.Lock()
	defer ttlMap.lock.Unlock()
	if ttlMap.itemMap == nil {
		ttlMap.itemMap = make(map[string]*item, 1024)
	}
	go func() {
		for range time.Tick(time.Second * time.Duration(cycleSec)) {
			ttlMap.lock.Lock()
			for key, item := range ttlMap.itemMap {
				if time.Now().UnixNano() >= item.expire {
					delete(ttlMap.itemMap, key)
				}
			}
			ttlMap.lock.Unlock()
		}
	}()
	return ttlMap
}

func (ttlMap *TTLMap) Set(key string, value interface{}, ex time.Duration) {
	ttlMap.lock.Lock()
	defer ttlMap.lock.Unlock()
	delete(ttlMap.itemMap, key)
	ttlMap.itemMap[key] = &item{value: value, expire: time.Now().Add(ex).UnixNano()}
}

func (ttlMap *TTLMap) Get(key string) (interface{}, bool) {
	ttlMap.lock.Lock()
	defer ttlMap.lock.Unlock()
	value, ok := ttlMap.itemMap[key]
	if !ok || time.Now().UnixNano() >= value.expire {
		delete(ttlMap.itemMap, key)
		return "", false
	}
	return value.value, true
}

func (ttlMap TTLMap) Len() int {
	ttlMap.lock.Lock()
	defer ttlMap.lock.Unlock()
	return len(ttlMap.itemMap)
}
