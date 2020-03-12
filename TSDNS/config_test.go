package TSDNS

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDomainMatcher(t *testing.T) {
	rules := []string{"*.qq.com", "baidu.com", ".taobao.com"}
	matcher := NewDomainMatcher(rules)

	match, ok := matcher.IsMatch("qq.com")
	assert.Equal(t, ok, false)
	match, ok = matcher.IsMatch("www.qq.com")
	assert.Equal(t, ok, true)
	assert.Equal(t, match, true)

	match, ok = matcher.IsMatch("baidu.com")
	assert.Equal(t, ok, true)
	assert.Equal(t, match, true)

	match, ok = matcher.IsMatch("taobao.com")
	assert.Equal(t, ok, false)
	match, ok = matcher.IsMatch("www.taobao.com")
	assert.Equal(t, ok, true)
	assert.Equal(t, match, true)
}
