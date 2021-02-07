package utils

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/Sirupsen/logrus"
)

const (
	loggerKey = "TS_LOGGER"
	logIDKey  = "TS_LOG_ID"
)

func ctxLog(level logrus.Level, ctx context.Context, format string, args ...interface{}) {
	var logger *logrus.Logger // 从context内读取logger
	if val, ok := ctx.Value(loggerKey).(*logrus.Logger); ok {
		logger = val
	} else {
		logger = logrus.StandardLogger()
	}
	var logID uint16 // 从context内读取log id
	if val, ok := ctx.Value(logIDKey).(uint16); ok {
		logID = val
	}
	location := "???.go:0" // 获取调用方位置
	if _, file, line, ok := runtime.Caller(2); ok {
		location = fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}
	// 统一输出格式
	format = fmt.Sprintf("[0x%04x] [%s] %s", logID, location, format)
	logger.Logf(level, format, args...)
}

// CtxDebug logger.Debugf的封装，logger从context中获取
func CtxDebug(ctx context.Context, format string, args ...interface{}) {
	ctxLog(logrus.DebugLevel, ctx, format, args...)
}

// CtxInfo logger.Infof的封装，logger从context中获取
func CtxInfo(ctx context.Context, format string, args ...interface{}) {
	ctxLog(logrus.InfoLevel, ctx, format, args...)
}

// CtxWarn logger.Warnf的封装，logger从context中获取
func CtxWarn(ctx context.Context, format string, args ...interface{}) {
	ctxLog(logrus.WarnLevel, ctx, format, args...)
}

// CtxWarn logger.Errorf的封装，logger从context中获取
func CtxError(ctx context.Context, format string, args ...interface{}) {
	ctxLog(logrus.ErrorLevel, ctx, format, args...)
}
