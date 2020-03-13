package GFWList

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
@@||ip.cn
`

func TestNewChecker(t *testing.T) {
	filename := "go_test_gfwlist.txt"
	// 文件不存在
	checker, err := NewCheckerByFn(filename, false)
	assert.NotEqual(t, err, nil)
	// 写入不正确内容
	content := base64.StdEncoding.EncodeToString([]byte(text)) + "???"
	_ = ioutil.WriteFile(filename, []byte(content), 0644)
	// 读取失败
	checker, err = NewCheckerByFn(filename, true)
	assert.NotEqual(t, err, nil)
	// 写入正确内容
	content = base64.StdEncoding.EncodeToString([]byte(text))
	_ = ioutil.WriteFile(filename, []byte(content), 0644)
	// 读取成功
	checker, err = NewCheckerByFn(filename, true)
	assert.NotEqual(t, checker, nil)
	assert.Equal(t, err, nil)
	// 判断空串
	blocked, ok := checker.IsBlocked("")
	assert.Equal(t, ok, false)
	// 规则.google.com不匹配google.com
	blocked, ok = checker.IsBlocked("google.com")
	assert.Equal(t, ok, false)
	// 但匹配test.google.com
	blocked, ok = checker.IsBlocked("test.google.com")
	assert.Equal(t, ok, true)
	// 匹配白名单@@||ip.cn
	blocked, ok = checker.IsBlocked("ip.cn")
	assert.Equal(t, ok, true)
	assert.Equal(t, blocked, false)
	// 匹配通配符*.youtube.*
	blocked, ok = checker.IsBlocked("www.youtube.com")
	assert.Equal(t, ok, true)
	assert.Equal(t, blocked, true)
	// 移除生成的文件
	_ = os.Remove(filename)
}
