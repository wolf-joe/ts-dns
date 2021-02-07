package model

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/agiledragon/gomonkey"
	"github.com/janeczku/go-ipset/ipset"
	"github.com/stretchr/testify/assert"
	"github.com/wolf-joe/ts-dns/cache"
	mock "github.com/wolf-joe/ts-dns/core/mocker"
	"github.com/wolf-joe/ts-dns/hosts"
	"github.com/wolf-joe/ts-dns/inbound"
	"github.com/wolf-joe/ts-dns/matcher"
	"github.com/wolf-joe/ts-dns/outbound"
)

func TestQueryLog(t *testing.T) {
	logConf := QueryLog{File: "/dev/null"}
	logger, err := logConf.GenLogger()
	assert.NotNil(t, logger)
	assert.Nil(t, err)

	mocker := mock.Mocker{}
	defer mocker.Reset()

	logConf.File = "aaa"
	mocker.FuncSeq(os.OpenFile, []gomonkey.Params{
		{nil, fmt.Errorf("err")}, {&os.File{}, nil},
	})
	logger, err = logConf.GenLogger()
	assert.Nil(t, logger)
	assert.NotNil(t, err)

	logger, err = logConf.GenLogger()
	assert.NotNil(t, logger)
	assert.Nil(t, err)
}

func TestGroup(t *testing.T) {
	mocker := mock.Mocker{}
	defer mocker.Reset()

	group := Group{}
	// 测试GenIPSet
	mocker.FuncSeq(ipset.New, []gomonkey.Params{
		{nil, fmt.Errorf("err")}, {&ipset.IPSet{}, nil},
	})
	s, err := group.GenIPSet() // ipset名称为空，直接返回nil
	assert.Nil(t, s)
	assert.Nil(t, err)
	group.IPSet = "test"
	s, err = group.GenIPSet() //ipset.New返回异常结果
	assert.Nil(t, s)
	assert.NotNil(t, err)
	s, err = group.GenIPSet() // ipset.New返回正常结果
	assert.NotNil(t, s)
	assert.Nil(t, err)

	// 测试GenCallers
	callers := group.GenCallers(context.Background())
	assert.Empty(t, callers)
	group.Socks5 = "1.1.1.1"
	group.DNS = []string{"1.1.1.1", "8.8.8.8:53/tcp"}              // 两个都有效
	group.DoT = []string{"1.1.1.1", "1.1.1.1@name"}                // 后一个有效
	group.DoH = []string{"not exists", "https://domain/dns-query"} // 后一个有效
	callers = group.GenCallers(context.Background())
	assert.Equal(t, len(callers), 4)

}

func TestConf(t *testing.T) {
	mocker := mock.Mocker{}
	defer mocker.Reset()

	conf := &Conf{}
	// 测试SetDefault
	conf.SetDefault()
	assert.NotEmpty(t, conf.Listen)
	assert.NotEmpty(t, conf.GFWList)
	assert.NotEmpty(t, conf.CNIP)
	// 测试GenCache
	conf.Cache = &Cache{}
	c := conf.GenCache()
	assert.NotNil(t, c)
	// 测试GenHostsReader
	conf.Hosts = map[string]string{"host": "1.1.1.1", "ne": "ne"}
	conf.HostsFiles = []string{"aaa", "bbb"} // 后一个NewReaderByFile正常
	mocker.FuncSeq(hosts.NewReaderByFile, []gomonkey.Params{
		{nil, fmt.Errorf("err")}, {&hosts.FileReader{}, nil},
	})
	ctx := context.Background()
	readers := conf.GenHostsReader(ctx)
	assert.Equal(t, len(readers), 2)
	assert.NotNil(t, readers[0].IP("host", false))
	// 测试GenGroups
	conf.Groups = map[string]*Group{"test": {Concurrent: true, FastestV4: true}}
	mocker.MethodSeq(&Group{}, "GenCallers", []gomonkey.Params{
		{nil}, {nil}, {nil}, {nil},
	})
	mocker.MethodSeq(&Group{}, "GenIPSet", []gomonkey.Params{
		{nil, fmt.Errorf("err")}, {nil, nil},
	})
	conf.Groups["test"].ECS = "1.1.1."
	groups, err := conf.GenGroups(ctx) // genECS失败
	assert.NotNil(t, err)
	assert.Nil(t, groups)
	conf.Groups["test"].ECS = "1.1.1.1"
	conf.Groups["test"].RulesFile = "???not_exists" // NewABPByFile失败
	groups, err = conf.GenGroups(ctx)
	assert.NotNil(t, err)
	assert.Nil(t, groups)
	conf.Groups["test"].RulesFile = "" // NewABPByFile成功
	groups, err = conf.GenGroups(ctx)  // GenIPSet失败
	assert.NotNil(t, err)
	assert.Nil(t, groups)
	groups, err = conf.GenGroups(ctx) // GenIPSet成功
	assert.Nil(t, err)
	assert.NotNil(t, groups)
}

func TestNewHandler(t *testing.T) {
	mocker := mock.Mocker{}
	defer mocker.Reset()

	mocker.FuncSeq(toml.DecodeFile, []gomonkey.Params{
		{nil, fmt.Errorf("err")},
	})
	ctx := context.Background()
	handler, err := NewHandler(ctx, "") // DecodeFile失败
	assert.Nil(t, handler)
	assert.NotNil(t, err)

	p := gomonkey.ApplyFunc(toml.DecodeFile,
		func(fn string, conf interface{}) (toml.MetaData, error) {
			conf.(*Conf).DisableIPv6 = true
			conf.(*Conf).DisableQTypes = []string{"HTTPS"}
			conf.(*Conf).Listen = ":53/tcp"
			return toml.MetaData{}, nil
		})
	defer p.Reset()

	mocker.FuncSeq(matcher.NewABPByFile, []gomonkey.Params{
		{nil, fmt.Errorf("err")}, {nil, nil}, {nil, nil}, {nil, nil},
		{nil, nil}, {nil, nil},
	})
	handler, err = NewHandler(ctx, "") // NewABPByFile失败
	assert.Nil(t, handler)
	assert.NotNil(t, err)
	mocker.FuncSeq(cache.NewRamSetByFile, []gomonkey.Params{
		{nil, fmt.Errorf("err")}, {nil, nil}, {nil, nil}, {nil, nil},
		{nil, nil},
	})
	handler, err = NewHandler(ctx, "") // NewRamSetByFile失败
	assert.Nil(t, handler)
	assert.NotNil(t, err)

	caller, _ := outbound.NewDoHCallerV2(ctx, "https://abc/", nil)
	caller.Exit()
	groups := map[string]*inbound.Group{"abc": {
		Callers: []outbound.Caller{caller},
	}}
	mocker.MethodSeq(&Conf{}, "GenGroups", []gomonkey.Params{
		{nil, fmt.Errorf("err")}, {groups, nil}, {nil, nil}, {nil, nil},
	})
	handler, err = NewHandler(ctx, "") // GenGroups失败
	assert.Nil(t, handler)
	assert.NotNil(t, err)
	mocker.MethodSeq(&QueryLog{}, "GenLogger", []gomonkey.Params{
		{nil, fmt.Errorf("err")}, {nil, nil}, {nil, nil},
	})
	handler, err = NewHandler(ctx, "") // GenLogger失败
	assert.Nil(t, handler)
	assert.NotNil(t, err)
	mocker.MethodSeq(&Conf{}, "GenCache", []gomonkey.Params{{nil}, {nil}})
	mocker.MethodSeq(handler, "IsValid", []gomonkey.Params{{false}, {true}})
	handler, err = NewHandler(ctx, "") // 验证配置失败
	assert.Nil(t, handler)
	assert.NotNil(t, err)
	handler, err = NewHandler(ctx, "") // 验证配置成功
	assert.NotNil(t, handler)
	assert.Nil(t, err)
}
