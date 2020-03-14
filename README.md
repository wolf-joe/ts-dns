# Telescope DNS

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/wolf-joe/ts-dns)](https://github.com/wolf-joe/ts-dns/releases)
[![Build Status](https://travis-ci.org/wolf-joe/ts-dns.svg?branch=master)](https://travis-ci.org/wolf-joe/ts-dns)
[![codecov](https://codecov.io/gh/wolf-joe/ts-dns/branch/master/graph/badge.svg)](https://codecov.io/gh/wolf-joe/ts-dns)
[![Go Report Card](https://goreportcard.com/badge/github.com/wolf-joe/ts-dns)](https://goreportcard.com/report/github.com/wolf-joe/ts-dns)
![GitHub](https://img.shields.io/github/license/wolf-joe/ts-dns)

> 简单易用的DNS分组/转发器

## 基本特性

* 默认基于GFWList进行分组；
* 支持DNS over UDP/TCP/TLS/HTTP；
* 支持通过socks5代理转发DNS请求；
* 支持多Hosts文件 + 自定义Hosts；
* 支持DNS查询缓存（包括EDNS Client Subnet）；
* 支持将查询结果添加至IPSet。

## 域名分组说明

1. 域名符合指定规则时将分配至对应组；
2. 域名符合GFWList黑名单时分配到`dirty`组；
3. 域名符合GFWList白名单时分配到`clean`组；
4. 以上条件均不符合时分配到`clean`组。

## 使用说明

1. 在[Releases页面](https://github.com/wolf-joe/ts-dns/releases)下载对应系统和平台的压缩包；
2. 解压后按需求编辑配置文件`ts-dns.toml`（可选）并运行进程：
  ```shell
  ./ts-dns
  ```

## 配置示例

> 完整配置文件参见`ts-dns.full.toml`

1. 默认配置（`ts-dns.toml`），开箱即用
  ```toml
  listen = ":53"
  gfwlist = "gfwlist.txt"

  [groups]
    [groups.clean]
    dns = ["119.29.29.29", "223.5.5.5", "114.114.114.114"]

    [groups.dirty]
    dns = [""]  # 省略
    rules = ["google.com"]
  ```

2. 指定hosts文件和自定义hosts
  ```toml
  # ...
  hosts_files = ["adaway.txt"]
  [hosts]
  "www.example.com" = "1.1.1.1"
  # ...
  ```

3. 使用socks5代理转发DNS请求
  ```toml
  # ...
    [groups.dirty]
    socks5 = "127.0.0.1:1080"
    # ...
  ```

4. 自定义域名分组
  ```toml
  # ...
    [groups.work]
    dns = ["10.1.1.1"]
    rules = ["company.com"]
    # ...
  ```

6. 动态添加IPSet记录（使用前请阅读`ts-dns.full.toml`对应说明）
  ```toml
  # ...
    [groups.dirty]
    ipset = "blocked"
    ipset_ttl = 86400
    # ...
  ```


## TODO

* 配置文件自动重载
* 默认使用ECS转发DNS请求
* DNS并发响应

## 依赖
* [github.com/miekg/dns](https://github.com/miekg/dns)
* [github.com/coreos/go-semver/semver](https://github.com/coreos/go-semver/semver)
* [github.com/BurntSushi/toml](https://github.com/BurntSushi/toml)

## 特别鸣谢
* [github.com/janeczku/go-ipset](https://github.com/janeczku/go-ipset)
* [github.com/arloan/prdns](https://github.com/arloan/prdns)
* [github.com/gfwlist/gfwlist](https://github.com/gfwlist/gfwlist)
