package inbound

import (
	"context"

	"github.com/miekg/dns"
	"github.com/wolf-joe/ts-dns/core/utils"
)

// Handler DNS请求处理器，用于将请求转发至上游DNS/其它DNS请求处理器
type Handler interface {
	Call(ctx context.Context, req, resp *dns.Msg) *dns.Msg
	String() string
}

// 判断是否出现递归处理
func recursiveDetect(ctx context.Context, handler Handler) (context.Context, bool) {
	var history map[Handler]bool
	if val, ok := ctx.Value(utils.RecHandleKey).(map[Handler]bool); ok {
		history = val
	} else {
		history = make(map[Handler]bool)
		ctx = context.WithValue(ctx, utils.RecHandleKey, history)
	}
	if history[handler] {
		return ctx, true
	} else {
		history[handler] = true
		return ctx, false
	}
}
