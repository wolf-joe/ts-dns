package GFWList

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewChecker(t *testing.T) {
	filename := "gfwlist.txt"
	checker, err := NewCheckerByFn("ne-"+filename, true)
	assert.True(t, checker == nil)
	assert.NotEqual(t, err, nil)
	checker, err = NewCheckerByFn("gfwlist-plain.txt", false)
	assert.NotEqual(t, checker, nil)
	assert.Equal(t, err, nil)

	checker, err = NewCheckerByFn(filename, true)
	assert.NotEqual(t, checker, nil)
	assert.Equal(t, err, nil)

	blocked, ok := checker.IsBlocked("")
	assert.Equal(t, blocked, false)
	assert.Equal(t, ok, false)
	blocked, ok = checker.IsBlocked("google.com") // blocked
	assert.Equal(t, blocked, true)
	assert.Equal(t, ok, true)
	blocked, ok = checker.IsBlocked("qq.com") // not blocked
	assert.Equal(t, blocked, false)
	assert.Equal(t, ok, true)
	blocked, ok = checker.IsBlocked("test.s3.amazonaws.com.") // wildcard
	assert.Equal(t, blocked, true)
	assert.Equal(t, ok, true)
	blocked, ok = checker.IsBlocked("unknown.com") // unknown domain
	assert.Equal(t, ok, false)
}
