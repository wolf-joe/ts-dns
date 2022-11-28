package utils

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func TestWithFields(t *testing.T) {
	ctx := NewCtx(nil, 0xffff)
	ctx = WithFields(ctx, logrus.Fields{"filename": "hello"})
	CtxWarn(ctx, "hello")
}
