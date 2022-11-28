package utils

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func TestCtxLog(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	ctx := NewCtx(nil, 0xeeee)
	CtxDebug(ctx, "this is debug level")
	CtxInfo(ctx, "this is info level")
	CtxWarn(ctx, "this is warn level")
	CtxError(ctx, "this is error level")

	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		DisableColors: true, FullTimestamp: true,
	})
	logger.SetLevel(logrus.DebugLevel)
	ctx = NewCtx(logger, 0xffff)
	format := "this is %s level"
	CtxDebug(ctx, format, "debug")
	CtxInfo(ctx, format, "info")
	CtxWarn(ctx, format, "warn")
	CtxError(ctx, format, "error")
}
