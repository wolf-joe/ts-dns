package core

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/config"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/outbound"
	"strconv"
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
	handlerPtr unsafe.Pointer // type: *handlerImpl
}

func (w *handlerWrapper) ReloadConfig(conf *config.Conf) error {
	// create & start new handler
	h, err := newHandle(conf)
	if err != nil {
		return fmt.Errorf("make new handler failed: %w", err)
	}
	h.start()
	// swap handler
	for {
		old := atomic.LoadPointer(&w.handlerPtr)
		if atomic.CompareAndSwapPointer(&w.handlerPtr, old, unsafe.Pointer(h)) {
			if old != nil {
				(*handlerImpl)(old).stop()
			}
			break
		}
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

func newHandle(conf *config.Conf) (*handlerImpl, error) {
	var err error
	h := &handlerImpl{
		disableQTypes: map[uint16]bool{},
		cache:         nil,
		hosts:         nil,
		groups:        nil,
		redirector:    nil,
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
	h.cache, err = cache.NewDNSCache(conf)
	if err != nil {
		return nil, fmt.Errorf("build cache failed: %w", err)
	}
	h.groups, err = outbound.BuildGroups(conf)
	if err != nil {
		return nil, fmt.Errorf("build groups failed: %w", err)
	}
	for _, group := range h.groups {
		if group.IsFallback() {
			h.fallbackGroup = group
		}
	}
	if h.fallbackGroup == nil {
		return nil, errors.New("fallback group not found")
	}

	// redirector todo
	return h, nil
}

// region impl
type handlerImpl struct {
	disableQTypes map[uint16]bool
	cache         cache.IDNSCache
	hosts         hosts.IDNSHosts
	groups        map[string]outbound.IGroup
	fallbackGroup outbound.IGroup
	redirector    IRedirector
}

func (h *handlerImpl) ServeDNS(writer dns.ResponseWriter, req *dns.Msg) {
	resp := h.handle(writer, req)
	if resp == nil {
		resp = new(dns.Msg)
	}
	if !resp.Response {
		resp.SetReply(req)
	}
	_ = writer.WriteMsg(resp)
	_ = writer.Close()
}

func (h *handlerImpl) handle(writer dns.ResponseWriter, req *dns.Msg) (resp *dns.Msg) {
	// region log
	_info := struct {
		blocked  bool
		hitHosts bool
		hitCache bool
		matched  outbound.IGroup
		fallback bool
		redirect outbound.IGroup
	}{}
	begin := time.Now()
	defer func() {
		fields := logrus.Fields{
			"cost":   strconv.FormatInt(time.Now().Sub(begin).Milliseconds(), 10) + "ms",
			"remote": writer.RemoteAddr().String(),
		}
		if _info.blocked {
			fields["blocked"] = true
		}
		if _info.hitHosts {
			fields["hit_hosts"] = true
		}
		if _info.hitCache {
			fields["hit_cache"] = true
		}
		if len(req.Question) > 0 {
			fields["question"] = req.Question[0].Name
			fields["q_type"] = dns.TypeToString[req.Question[0].Qtype]
		}
		if _info.matched != nil {
			fields["group"] = _info.matched
		}
		if _info.fallback {
			fields["fallback"] = true
		}
		if _info.redirect != nil {
			fields["redir"] = _info.redirect.String()
		}
		if resp == nil {
			fields["answer"] = "nil"
		} else {
			fields["answer"] = len(resp.Answer)
		}
		if _info.blocked || _info.hitCache || _info.hitHosts {
			logrus.WithFields(fields).Debug()
		} else {
			logrus.WithFields(fields).Info()
		}
	}()
	// endregion
	for _, question := range req.Question {
		if h.disableQTypes[question.Qtype] {
			_info.blocked = true
			return nil // disabled
		}
	}
	if resp = h.hosts.Get(req); resp != nil {
		_info.hitHosts = true
		return resp
	}
	if resp = h.cache.Get(req); resp != nil {
		_info.hitCache = true
		return resp
	}

	// handle by matched group
	var matched outbound.IGroup
	for _, group := range h.groups {
		if group.Match(req) {
			matched = group
			resp = group.Handle(req)
			break
		}
	}
	if matched == nil {
		matched = h.fallbackGroup
		resp = h.fallbackGroup.Handle(req)
		_info.fallback = true
	}
	_info.matched = matched

	// redirect
	if h.redirector != nil {
		if group := h.redirector.Redirect(req, resp); group != nil {
			matched = group
			resp = group.Handle(req)
			_info.redirect = group
		}
	}

	// finally
	matched.PostProcess(req, resp)
	h.cache.Set(req, resp)
	return resp
}

func (h *handlerImpl) start() {
	for _, group := range h.groups {
		group.Start(h)
	}
	h.cache.Start(time.Minute)
	logrus.Debugf("start handler success")
}

func (h *handlerImpl) stop() {
	logrus.Debugf("stop handler")
	for _, group := range h.groups {
		group.Stop()
	}
	h.cache.Stop()
	logrus.Debugf("stop handler success")
}

// endregion
