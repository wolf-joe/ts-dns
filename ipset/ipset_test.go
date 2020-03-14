package ipset

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestIPSet(t *testing.T) {
	name := "go_test_ipset"
	// 创建失败
	ipset, err := New(name, "hash:??", &Params{})
	assert.True(t, ipset == nil)
	assert.True(t, err != nil)
	// 创建成功
	ipset, err = New(name, "hash:ip", &Params{})
	assert.True(t, ipset != nil)
	assert.True(t, err == nil)
	if ipset == nil {
		return
	}
	// 添加ip
	_ = ipset.Add("1.1.1.1", 1)
	_ = ipset.AddOption("1.1.1.2", "-quiet", 2)
	// 查询成功
	ok, _ := ipset.Test("1.1.1.1")
	assert.True(t, ok)
	time.Sleep(time.Millisecond * 1100)
	ok, _ = ipset.Test("1.1.1.2")
	assert.True(t, ok)
	// 记录失效，查询失败
	ok, _ = ipset.Test("1.1.1.1")
	assert.True(t, !ok)
	// 移除ip
	_ = ipset.Del("1.1.1.2")
	ok, _ = ipset.Test("1.1.1.2")
	assert.True(t, !ok)
	// 导入记录列表
	_ = ipset.Refresh([]string{"1.1.1.3"})
	ok, _ = ipset.Test("1.1.1.3")
	assert.True(t, ok)
	// 清空ipset
	_ = ipset.Flush()
	ok, _ = ipset.Test("1.1.1.3")
	assert.True(t, !ok)
	ips, _ := ipset.List()
	assert.True(t, len(ips) == 1)
	assert.True(t, ips[0] == "")
	// 移除ipset
	_ = ipset.Destroy()
	// 移除所有ipset，最好只在travis.ci上执行
	_ = DestroyAll()
	_ = destroyAll()
}
