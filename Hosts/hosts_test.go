package Hosts

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestNewReader(t *testing.T) {
	content := "# comment\n\n 256.0.0.0 ne\n" +
		" 127.0.0.1 localhost \n \n gggg::0 ip6-ne \n ::1 ip6-localhost "
	reader := NewTextReader(content)
	assert.Equal(t, reader.V4("ne"), "")
	assert.Equal(t, reader.V4("localhost"), "127.0.0.1")
	assert.Equal(t, reader.V6("ip6-ne"), "")
	assert.Equal(t, reader.V6("ip6-localhost"), "::1")
	assert.Equal(t, reader.GenRecord("ne", dns.TypeA), "")
	expect := "localhost 0 IN A 127.0.0.1"
	assert.Equal(t, reader.GenRecord("localhost", dns.TypeA), expect)
	expect = "ip6-localhost 0 IN AAAA ::1"
	assert.Equal(t, reader.GenRecord("ip6-localhost", dns.TypeAAAA), expect)
}

func TestNewFileReader(t *testing.T) {
	filename := "auto_remove_hosts_file"
	reader, err := NewFileReader(filename, 0)
	assert.True(t, reader == nil)
	assert.NotEqual(t, err, nil)

	content := "127.0.0.1 localhost\n::1 ip6-localhost"
	_ = ioutil.WriteFile(filename, []byte(content), 0644)
	reader, err = NewFileReader(filename, time.Second)
	assert.Equal(t, err, nil)
	assert.NotEqual(t, reader, nil)
	assert.Equal(t, reader.V4("localhost"), "127.0.0.1")
	assert.Equal(t, reader.V6("ip6-localhost"), "::1")
	expect := "localhost 0 IN A 127.0.0.1"
	assert.Equal(t, reader.GenRecord("localhost", dns.TypeA), expect)

	content = "127.0.1.1 localhost\n::2 ip6-localhost"
	_ = ioutil.WriteFile(filename, []byte(content), 0644)
	time.Sleep(time.Second)
	assert.Equal(t, reader.V4("localhost"), "127.0.1.1")
	assert.Equal(t, reader.V6("ip6-localhost"), "::2")
	expect = "ip6-localhost 0 IN AAAA ::2"
	assert.Equal(t, reader.GenRecord("ip6-localhost", dns.TypeAAAA), expect)

	_ = os.Remove(filename)
}
