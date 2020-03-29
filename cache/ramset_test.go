package cache

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net"
	"os"
	"testing"
)

func TestRamSet(t *testing.T) {
	text := "  1.2.4.8  \n 8.8.8.8 \n 1.0.0.0/8 \n  192.168.1.1/33 \n ::1 \n ::2 "
	filename := "go_test_ips_file"
	_ = ioutil.WriteFile(filename, []byte(text), 0644)
	// 读取失败
	matcher, err := NewRamSetByFile(filename + "_ne")
	assert.True(t, err != nil)
	// 读取成功
	matcher, err = NewRamSetByFile(filename)
	assert.True(t, matcher != nil)
	assert.True(t, err == nil)
	if matcher != nil {
		assert.False(t, matcher.Contain(nil))
		assert.False(t, matcher.Contain(net.ParseIP("999.9.9.9")))
		assert.True(t, matcher.Contain(net.ParseIP("8.8.8.8")))
		assert.True(t, matcher.Contain(net.ParseIP("1.254.254.254")))
		assert.False(t, matcher.Contain(net.ParseIP("192.168.1.1")))
	}
	_ = os.Remove(filename)
}
