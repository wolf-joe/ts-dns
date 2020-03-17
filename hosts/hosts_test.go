package hosts

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestNewTextReader(t *testing.T) {
	content := "# comment\n\n 256.0.0.0 ne\n" +
		" 127.0.0.1 localhost \n \n gggg::0 ip6-ne \n ::1 ip6-localhost "
	reader := NewReaderByText(content)
	assert.Equal(t, reader.IP("ne", false), "")
	assert.Equal(t, reader.IP("localhost", false), "127.0.0.1")
	assert.Equal(t, reader.IP("ip6-ne", true), "")
	assert.Equal(t, reader.IP("ip6-localhost", true), "::1")
	assert.Equal(t, reader.Record("ne", false), "")
	expect := "localhost 0 IN A 127.0.0.1"
	assert.Equal(t, reader.Record("localhost", false), expect)
	expect = "ip6-localhost 0 IN AAAA ::1"
	assert.Equal(t, reader.Record("ip6-localhost", true), expect)
}

func TestNewFileReader(t *testing.T) {
	filename := "go_test_hosts_file"
	reader, err := NewReaderByFile(filename, 0)
	assert.True(t, reader == nil)
	assert.NotEqual(t, err, nil)

	// 写入测试文件
	content := "127.0.0.1 localhost\n::1 ip6-localhost"
	_ = ioutil.WriteFile(filename, []byte(content), 0644)
	reader, err = NewReaderByFile(filename, time.Second)
	assert.Equal(t, err, nil)
	assert.Equal(t, reader.IP("localhost", false), "127.0.0.1")
	assert.Equal(t, reader.IP("ip6-localhost", true), "::1")
	expect := "localhost 0 IN A 127.0.0.1"
	assert.Equal(t, reader.Record("localhost", false), expect)

	content = "127.0.1.1 localhost\n::2 ip6-localhost"
	_ = ioutil.WriteFile(filename, []byte(content), 0644)
	// 1秒之后自动重载hosts
	time.Sleep(time.Second)
	assert.Equal(t, reader.IP("localhost", false), "127.0.1.1")
	assert.Equal(t, reader.IP("ip6-localhost", true), "::2")
	expect = "ip6-localhost 0 IN AAAA ::2"
	assert.Equal(t, reader.Record("ip6-localhost", true), expect)

	_ = os.Remove(filename)
}
