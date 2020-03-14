package matcher

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
)

var text = `[AutoProxy]
!comment
|http://1.1.1.1
unknown
|https://*.youtube.com/path
.google.com
@@||cip.cc
@@||*.cn
`

func TestNewChecker(t *testing.T) {
	filename := "go_test_adblock.txt"
	// 文件不存在
	matcher, err := NewABPByFile(filename, false)
	assert.NotEqual(t, err, nil)
	// 写入不正确内容
	content := base64.StdEncoding.EncodeToString([]byte(text)) + "???"
	_ = ioutil.WriteFile(filename, []byte(content), 0644)
	// 读取失败
	matcher, err = NewABPByFile(filename, true)
	assert.NotEqual(t, err, nil)
	// 写入正确内容
	content = base64.StdEncoding.EncodeToString([]byte(text))
	_ = ioutil.WriteFile(filename, []byte(content), 0644)
	// 读取成功
	matcher, err = NewABPByFile(filename, true)
	assert.NotEqual(t, matcher, nil)
	assert.Equal(t, err, nil)
	// 移除生成的文件
	_ = os.Remove(filename)

	// 判断空串
	matched, ok := matcher.Match("")
	assert.Equal(t, ok, false)
	// 规则.google.com不匹配google.com
	matched, ok = matcher.Match("google.com")
	assert.Equal(t, ok, false)
	// 但匹配test.google.com
	matched, ok = matcher.Match("test.google.com")
	assert.Equal(t, ok, true)
	// 匹配白名单@@||cip.cc
	matched, ok = matcher.Match("cip.cc.")
	assert.Equal(t, ok, true)
	assert.Equal(t, matched, false)
	// 匹配白名单@@||*.cn
	matched, ok = matcher.Match("ip.cn")
	assert.Equal(t, ok, true)
	assert.Equal(t, matched, false)
	// 匹配通配符*.youtube.*
	matched, ok = matcher.Match("www.youtube.com")
	assert.Equal(t, ok, true)
	assert.Equal(t, matched, true)
}
