package utils

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/Sirupsen/logrus"
)

func ctxLog(ctx context.Context, level logrus.Level, format string, args ...interface{}) {
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
	var entry *logrus.Entry // 从context内读取fields
	if val, ok := ctx.Value(fieldsKey).(logrus.Fields); ok {
		entry = logger.WithFields(val)
	} else {
		entry = logrus.NewEntry(logger)
	}
	location := "???.go:0" // 获取调用方位置
	if _, file, line, ok := runtime.Caller(2); ok {
		location = fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}
	// 统一输出格式
	format = fmt.Sprintf("[0x%04x] [%s] %s", logID, location, format)
	entry.Logf(level, format, args...)
}

// CtxDebug logger.Debugf的封装，logger从context中获取
func CtxDebug(ctx context.Context, format string, args ...interface{}) {
	ctxLog(ctx, logrus.DebugLevel, format, args...)
}

// CtxInfo logger.Infof的封装，logger从context中获取
func CtxInfo(ctx context.Context, format string, args ...interface{}) {
	ctxLog(ctx, logrus.InfoLevel, format, args...)
}

// CtxWarn logger.Warnf的封装，logger从context中获取
func CtxWarn(ctx context.Context, format string, args ...interface{}) {
	ctxLog(ctx, logrus.WarnLevel, format, args...)
}

// CtxError logger.Errorf的封装，logger从context中获取
func CtxError(ctx context.Context, format string, args ...interface{}) {
	ctxLog(ctx, logrus.ErrorLevel, format, args...)
}
