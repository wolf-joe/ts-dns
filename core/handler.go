package core

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/hosts"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
)

// region interface

// IHandler ts-dns service handler
type IHandler interface {
	dns.Handler
	ReloadConfig(conf *config.Conf) error
	Stop()
}

// NewHandler Build a service can handle dns request, life cycle start immediately
func NewHandler(conf *config.Conf) (IHandler, error) {
	h := new(handlerWrapper)
	if err := h.ReloadConfig(conf); err != nil {
		return nil, err
	}
	return h, nil
}

// endregion

// region wrapper
var (
	_ IHandler = &handlerWrapper{}
)

type handlerWrapper struct {
	handlerPtr unsafe.Pointer
}

func (w *handlerWrapper) ReloadConfig(conf *config.Conf) error {
	// create & start new handler
	h, err := newHandle(conf)
	if err != nil {
		return fmt.Errorf("make new handler failed: %w", err)
	}
	h.start()
	// stop old handler
	old := atomic.LoadPointer(&w.handlerPtr)
	if old != nil {
		(*handlerImpl)(old).stop()
	}
	// swap handler
	if !atomic.CompareAndSwapPointer(&w.handlerPtr, old, unsafe.Pointer(h)) {
		h.stop()
		return fmt.Errorf("CAS failed when swap handler")
	}
	return nil
}

func (w *handlerWrapper) ServeDNS(writer dns.ResponseWriter, req *dns.Msg) {
	(*handlerImpl)(atomic.LoadPointer(&w.handlerPtr)).ServeDNS(writer, req)
}

func (w *handlerWrapper) Stop() {
	for {
		old := atomic.LoadPointer(&w.handlerPtr)
		if old == nil {
			return
		}
		if atomic.CompareAndSwapPointer(&w.handlerPtr, old, nil) {
			(*handlerImpl)(old).stop()
			return
		}
	}
}

// endregion

// region impl
type handlerImpl struct {
	disableQTypes map[uint16]bool
	cache         cache.IDNSCache
	hosts         hosts.IDNSHosts
	groups        map[string]IGroup
	Redirector    IRedirector
}

func (h *handlerImpl) ServeDNS(writer dns.ResponseWriter, req *dns.Msg) {
	resp := h.handle(req)
	if resp == nil {
		resp = new(dns.Msg)
	}
	if !resp.Response {
		resp.SetReply(req)
	}
	_ = writer.WriteMsg(resp)
	_ = writer.Close()
}

func (h *handlerImpl) handle(req *dns.Msg) (resp *dns.Msg) {
	for _, question := range req.Question {
		if h.disableQTypes[question.Qtype] {
			return nil // disabled
		}
	}
	if resp = h.hosts.Get(req); resp != nil {
		return resp
	}
	if resp = h.cache.Get(req); resp != nil {
		return resp
	}
	for _, group := range h.groups {
		if group.Match(req) {
			resp = group.Handle(req)
			break
		}
	}
	if resp != nil && h.Redirector != nil {
		if group := h.Redirector.Redirect(req, resp); group != nil {
			resp = group.Handle(req)
		}
	}
	if resp != nil {
		h.cache.Set(req, resp)
	}
	return resp
}

func (h *handlerImpl) start() {
	for _, group := range h.groups {
		group.Start()
	}
	h.cache.Start(time.Minute)
}

func (h *handlerImpl) stop() {
	for _, group := range h.groups {
		group.Stop()
	}
	h.cache.Stop()
}

func newHandle(conf *config.Conf) (*handlerImpl, error) {
	var err error
	h := &handlerImpl{
		disableQTypes: map[uint16]bool{},
		cache:         nil,
		hosts:         nil,
		groups:        nil,
		Redirector:    nil,
	}
	// disable query types
	if conf.DisableIPv6 {
		h.disableQTypes[dns.TypeAAAA] = true
	}
	for _, qTypeStr := range conf.DisableQTypes {
		qTypeStr = strings.ToUpper(qTypeStr)
		if _, exists := dns.StringToType[qTypeStr]; !exists {
			return nil, fmt.Errorf("unknown query type: %q", qTypeStr)
		}
		h.disableQTypes[dns.StringToType[qTypeStr]] = true
	}

	// hosts & cache
	h.hosts, err = hosts.NewDNSHosts(conf)
	if err != nil {
		return nil, fmt.Errorf("build hosts failed: %w", err)
	}
	h.cache, err = cache.NewDNSCache2(conf)
	if err != nil {
		return nil, fmt.Errorf("build cache failed: %w", err)
	}
	// group todo
	// redirector todo
	return h, nil
}

// endregion
