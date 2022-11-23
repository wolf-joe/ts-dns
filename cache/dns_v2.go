package cache

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/valyala/fastrand"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/core/common"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IDNSCache cache dns response for dns request
type IDNSCache interface {
	// Get find cached response
	Get(req *dns.Msg) *dns.Msg
	// Set save response to cache
	Set(req *dns.Msg, resp *dns.Msg)
	// Start life cycle begin
	Start(cleanTick time.Duration)
	// Stop life cycle end
	Stop()
}

func NewDNSCache2(conf *config.Conf) (IDNSCache, error) {
	minTTL, maxTTL, maxSize := DefaultMinTTL, DefaultMaxTTL, DefaultSize
	if conf.Cache.MinTTL > 0 {
		minTTL = time.Second * time.Duration(conf.Cache.MinTTL)
	}
	if conf.Cache.MaxTTL > 0 {
		maxTTL = time.Second * time.Duration(conf.Cache.MaxTTL)
	}
	if minTTL > maxTTL {
		return nil, fmt.Errorf("min ttl(%d) larger than max ttl(%d)", conf.Cache.MinTTL, conf.Cache.MaxTTL)
	}
	maxSize = conf.Cache.Size
	c := &dnsCache{
		items:   map[string]cacheItem{},
		lock:    new(sync.RWMutex),
		stopCh:  make(chan struct{}),
		stopped: make(chan struct{}),
		maxSize: maxSize,
		minTTL:  minTTL,
		maxTTL:  maxTTL,
	}
	return c, nil
}

var (
	_ IDNSCache = &dnsCache{}
)

type cacheItem struct {
	resp      *dns.Msg
	expiredAt int64
}

type dnsCache struct {
	items   map[string]cacheItem
	lock    *sync.RWMutex
	stopCh  chan struct{}
	stopped chan struct{}

	maxSize int
	minTTL  time.Duration
	maxTTL  time.Duration
}

func (c *dnsCache) cacheKey(req *dns.Msg) string {
	question := req.Question[0]
	key := question.Name + strconv.FormatInt(int64(question.Qtype), 10)
	if subnet := common.FormatECS(req); subnet != "" {
		key += "." + subnet
	}
	return strings.ToLower(key)
}

func (c *dnsCache) Get(req *dns.Msg) *dns.Msg {
	if c.maxSize <= 0 {
		return nil
	}
	// check cache
	key := c.cacheKey(req)
	c.lock.RLock()
	item, exists := c.items[key]
	c.lock.RUnlock()
	if !exists {
		return nil
	}
	// ttl countdown
	ttl := item.expiredAt - time.Now().Unix()
	if ttl <= 0 {
		// remove expired item
		c.lock.Lock()
		delete(c.items, key)
		c.lock.Unlock()
		return nil
	}
	r := item.resp.Copy()
	for i := 0; i < len(r.Answer); i++ {
		r.Answer[i].Header().Ttl = uint32(ttl)
	}
	// shuffle ip
	first := uint32(len(r.Answer))
	for ; first > 0; first-- {
		if t := r.Answer[first-1].Header().Rrtype; t != dns.TypeA && t != dns.TypeAAAA {
			break
		}
	}
	if ips := r.Answer[first:]; len(ips) > 1 {
		for i := uint32(len(ips) - 1); i > 0; i-- {
			j := fastrand.Uint32n(i + 1)
			ips[i], ips[j] = ips[j], ips[i]
		}
	}
	return r
}

func (c *dnsCache) Set(req *dns.Msg, resp *dns.Msg) {
	if c.maxSize <= 0 || resp == nil || len(resp.Answer) == 0 {
		return
	}
	// check size
	c.lock.RLock()
	length := len(c.items)
	c.lock.RUnlock()
	if length >= c.maxSize {
		return
	}
	// reset ttl
	key := c.cacheKey(req)
	var expire = c.maxTTL
	for _, answer := range resp.Answer {
		if ttl := time.Duration(answer.Header().Ttl) * time.Second; ttl < expire {
			expire = ttl
		}
	}
	if expire < c.minTTL {
		expire = c.minTTL
	}
	for i := 0; i < len(resp.Answer); i++ {
		resp.Answer[i].Header().Ttl = uint32(expire.Seconds())
	}
	// set cache
	expiredAt := time.Now().Add(expire).Unix()
	c.lock.Lock()
	c.items[key] = cacheItem{resp: resp, expiredAt: expiredAt}
	c.lock.Unlock()
}

func (c *dnsCache) Start(cleanTick time.Duration) {
	go func() {
		tk := time.Tick(cleanTick)
		for {
			select {
			case <-c.stopCh:
				close(c.stopped)
				return
			case <-tk:
				// clean expired key
				c.lock.Lock()
				for key, item := range c.items {
					if time.Now().Unix() >= item.expiredAt {
						delete(c.items, key)
					}
				}
				c.lock.Unlock()
			}
		}
	}()
}

func (c *dnsCache) Stop() {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	<-c.stopped
}
