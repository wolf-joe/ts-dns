package utils

import (
	"context"

	"github.com/Sirupsen/logrus"
)

type ctxKey string

const (
	loggerKey ctxKey = "TS_LOGGER"
	logIDKey  ctxKey = "TS_LOG_ID"
	fieldsKey ctxKey = "TS_LOG_FIELDS"
	// 是否被递归处理
	RecHandleKey ctxKey = "TS_REC_HANDLE"
)

// NewCtx 返回一个已放入logger的ctx，用来传递给CtxInfo
func NewCtx(logger *logrus.Logger, logID uint16) context.Context {
	ctx := context.Background()
	if logger != nil {
		ctx = context.WithValue(ctx, loggerKey, logger)
	}
	ctx = context.WithValue(ctx, logIDKey, logID)
	return ctx
}

// WithFields 在ctx内放入用于打印日志的fields，已有时会被覆盖
func WithFields(ctx context.Context, fields logrus.Fields) context.Context {
	return context.WithValue(ctx, fieldsKey, fields)
}
