package model

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/go-ipset/ipset"
	"github.com/wolf-joe/ts-dns/cache"
	"github.com/wolf-joe/ts-dns/core/utils"
	"github.com/wolf-joe/ts-dns/core/utils/mock"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/matcher"
)

func TestNewDNSCache(t *testing.T) {
	assert.NotNil(t, newDNSCache(CacheConf{Size: 1, MinTTL: 60, MaxTTL: 86400}))
}

func TestNewLogCfg(t *testing.T) {
	ctx := utils.NewCtx(nil, 0xffff)
	mocker := new(mock.Mocker)
	defer mocker.Reset()
	mocker.Func(os.OpenFile, func(name string, _ int, _ os.FileMode) (*os.File, error) {
		if name == "error" {
			return nil, errors.New("mock error")
		}
		return &os.File{}, nil
	})
	mocker.Method(&os.File{}, "Close", func(*os.File) error {
		return errors.New("close file mock error")
	})

	cfg := &QueryLog{File: "", IgnoreQTypes: nil,
		IgnoreHosts: false, IgnoreCache: false}
	logCfg, err := newLogCfg(ctx, cfg)
	assert.Nil(t, err)
	assert.NotNil(t, logCfg)
	logCfg.Exit(ctx)

	cfg.File = "error"
	logCfg, err = newLogCfg(ctx, cfg)
	assert.NotNil(t, err)
	assert.Nil(t, logCfg)

	cfg.File = "abc"
	logCfg, err = newLogCfg(ctx, cfg)
	assert.Nil(t, err)
	assert.NotNil(t, logCfg)
	logCfg.Exit(ctx)

	cfg.File = "/dev/null"
	logCfg, err = newLogCfg(ctx, cfg)
	assert.Nil(t, err)
	assert.NotNil(t, logCfg)
	logCfg.Exit(ctx)
}

func TestParseListen(t *testing.T) {
	addr, network := parseListen("")
	assert.Equal(t, ":53", addr)
	assert.Equal(t, "", network)

	addr, network = parseListen(":5353")
	assert.Equal(t, ":5353", addr)
	assert.Equal(t, "", network)

	addr, network = parseListen("/udp")
	assert.Equal(t, ":53", addr)
	assert.Equal(t, "udp", network)

	addr, network = parseListen("127.0.0.1:5353/tcp")
	assert.Equal(t, "127.0.0.1:5353", addr)
	assert.Equal(t, "tcp", network)

	addr, network = parseListen("???:::???///???")
	assert.Equal(t, "???:::???", addr)
	assert.Equal(t, "//???", network)
}

func TestNewDNSCaller(t *testing.T) {
	_, err := newDNSCaller("", nil)
	assert.NotNil(t, err)
	_, err = newDNSCaller("1.1.1.1:abc", nil)
	assert.NotNil(t, err)
	_, err = newDNSCaller("1.1.1.1:53/???", nil)
	assert.NotNil(t, err)
	_, err = newDNSCaller("1.1.1.1:53/udp", nil)
	assert.Nil(t, err)
}

func TestNewDoTCaller(t *testing.T) {
	_, err := newDoTCaller("", nil)
	assert.NotNil(t, err)
	_, err = newDoTCaller("1.1.1.1", nil)
	assert.NotNil(t, err)
	_, err = newDoTCaller("1.1.1.1:853", nil)
	assert.NotNil(t, err)
	_, err = newDoTCaller("1.1.1.1:853@", nil)
	assert.NotNil(t, err)
	_, err = newDoTCaller("1.1.1.1:???@abc", nil)
	assert.NotNil(t, err)
	_, err = newDoTCaller("1.1.1.1:853@abc", nil)
	assert.Nil(t, err)
	_, err = newDoTCaller(":853@abc", nil)
	assert.NotNil(t, err)
}

func TestNewIPSet(t *testing.T) {
	ctx := utils.NewCtx(nil, 0xffff)
	mocker := new(mock.Mocker)
	defer mocker.Reset()
	mocker.Func(ipset.New, func(name string, _ string, _ *ipset.Params) (*ipset.IPSet, error) {
		if name == "error" {
			return nil, errors.New("error")
		}
		return &ipset.IPSet{}, nil
	})

	val, err := newIPSet(ctx, "", 100)
	assert.Nil(t, err)
	assert.Nil(t, val)
	val, err = newIPSet(ctx, "error", 100)
	assert.NotNil(t, err)
	assert.Nil(t, val)
	val, err = newIPSet(ctx, "abc", 100)
	assert.Nil(t, err)
	assert.NotNil(t, val)
}

func TestNewCallers(t *testing.T) {
	ctx := utils.NewCtx(nil, 0xffff)
	socks5 := "abc"

	var dns, dot, doh []string

	callers, err := newCallers(ctx, socks5, dns, dot, doh)
	assert.Empty(t, callers)
	assert.Nil(t, err)

	dns = []string{":abc"}
	_, err = newCallers(ctx, socks5, dns, dot, doh)
	assert.NotNil(t, err)

	dns = []string{"1.1.1.1"}
	dot = []string{":abc"}
	_, err = newCallers(ctx, socks5, dns, dot, doh)
	assert.NotNil(t, err)

	dot = []string{"8.8.8.8@dns.google"}
	doh = []string{":abc"}
	_, err = newCallers(ctx, socks5, dns, dot, doh)
	assert.NotNil(t, err)

	doh = []string{"https://dns.google/"}
	callers, err = newCallers(ctx, socks5, dns, dot, doh)
	assert.Nil(t, err)
	assert.NotNil(t, callers)
}

func TestNewGroup(t *testing.T) {
	ctx := utils.NewCtx(nil, 0xffff)
	mocker := new(mock.Mocker)
	defer mocker.Reset()
	mocker.Func(ipset.New, func(name string, _ string, _ *ipset.Params) (*ipset.IPSet, error) {
		if name == "error" {
			return nil, errors.New("error")
		}
		return &ipset.IPSet{}, nil
	})
	name := "test"
	conf := &Group{}

	group, err := newGroup(ctx, name, conf)
	assert.Nil(t, err)
	assert.NotNil(t, group)

	conf.RulesFile = "???"
	_, err = newGroup(ctx, name, conf)
	assert.NotNil(t, err)

	conf.RulesFile = ""
	conf.DNS = []string{":???"}
	_, err = newGroup(ctx, name, conf)
	assert.NotNil(t, err)

	conf.DNS = nil
	conf.IPSet = "error"
	_, err = newGroup(ctx, name, conf)
	assert.NotNil(t, err)

	conf.IPSet = ""
	conf.ECS = "???"
	_, err = newGroup(ctx, name, conf)
	assert.NotNil(t, err)

	conf.ECS = ""
	conf.FastestV4 = true
	group, err = newGroup(ctx, name, conf)
	assert.Nil(t, err)
	assert.NotNil(t, group)
}

func TestNewDNSServer(t *testing.T) {
	conf := Conf{Logger: &QueryLog{}, DisableIPv6: true}
	ctx := utils.NewCtx(nil, 0xffff)
	mocker := new(mock.Mocker)
	defer mocker.Reset()
	mocker.Func(os.OpenFile, func(name string, _ int, _ os.FileMode) (*os.File, error) {
		if name == "error" {
			return nil, errors.New("mock error")
		}
		return &os.File{}, nil
	})
	mocker.Func(hosts.NewReaderByFile, func(fn string, _ time.Duration) (*hosts.FileReader, error) {
		if fn == "error" {
			return nil, errors.New("mock error")
		}
		return &hosts.FileReader{}, nil
	})

	conf.Groups = map[string]*Group{"test": {
		ECS: "123",
	}}
	_, err := newDNSServer(ctx, conf)
	assert.NotNil(t, err)
	conf.Groups["test"].ECS = ""
	_, err = newDNSServer(ctx, conf)
	assert.Nil(t, err)

	conf.Logger.File = "error"
	_, err = newDNSServer(ctx, conf)
	assert.NotNil(t, err)
	conf.Logger.File = ""
	_, err = newDNSServer(ctx, conf)
	assert.Nil(t, err)

	conf.HostsFiles = []string{"error", "test"}
	conf.Hosts = map[string]string{"taobao.com": "1.1.1.1"}
	_, err = newDNSServer(ctx, conf)
	assert.Nil(t, err)

	conf.HostsFiles = nil
	conf.GFWList = "gfw.txt"
	_, err = newDNSServer(ctx, conf)
	assert.NotNil(t, err)
}

func TestNewDNSServerFromFile(t *testing.T) {
	ctx := utils.NewCtx(nil, 0xffff)
	mocker := new(mock.Mocker)
	defer mocker.Reset()
	mocker.Func(ioutil.ReadFile, func(filename string) ([]byte, error) {
		if filename == "error" {
			return nil, errors.New("file not exists")
		}
		return nil, nil
	})

	_, err := NewDNSServerFromFile(ctx, "error")
	assert.NotNil(t, err)

	serv, err := NewDNSServerFromFile(ctx, "abc")
	assert.Nil(t, err)
	assert.NotNil(t, serv)
}

func TestNewDNSServerFromText(t *testing.T) {
	ctx := utils.NewCtx(nil, 0xffff)
	mocker := new(mock.Mocker)
	defer mocker.Reset()
	mocker.Func(ioutil.ReadFile, func(filename string) ([]byte, error) {
		if filename == "error" {
			return nil, errors.New("file not exists")
		}
		return nil, nil
	})

	_, err := NewDNSServerFromText(ctx, "???")
	assert.NotNil(t, err)
	_, err = NewDNSServerFromText(ctx, "")
	assert.Nil(t, err)
}

func TestCompatibleOld(t *testing.T) {
	ctx := utils.NewCtx(nil, 0xffff)
	mocker := new(mock.Mocker)
	defer mocker.Reset()
	text := `listen = ":53"
gfwlist = "error"
cnip = "error"

[groups]
  [groups.clean]
  dns = ["223.5.5.5", "114.114.114.114"]
  concurrent = true

  [groups.dirty]
  dns = ["208.67.222.222:5353", "176.103.130.130:5353"]`
	var conf = Conf{Logger: &QueryLog{}}
	if _, err := toml.Decode(text, &conf); err != nil {
		panic(err)
	}
	mocker.Func(matcher.NewABPByFile, func(fn string, _ bool) (*matcher.ABPlus, error) {
		if fn == "error" {
			return nil, errors.New("mock by error")
		}
		return &matcher.ABPlus{}, nil
	})
	mocker.Func(cache.NewRamSetByFile, func(fn string) (*cache.RamSet, error) {
		if fn == "error" {
			return nil, errors.New("mock by error")
		}
		return &cache.RamSet{}, nil
	})

	serv, err := newDNSServer(ctx, conf)
	assert.NotNil(t, err)
	assert.Nil(t, serv)

	conf.GFWList = "gfwlist.txt"
	serv, err = newDNSServer(ctx, conf)
	assert.NotNil(t, err)
	assert.Nil(t, serv)

	conf.CNIP = "cnip.txt"
	serv, err = newDNSServer(ctx, conf)
	assert.Nil(t, err)
	assert.NotNil(t, serv)
}
