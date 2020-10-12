# Telescope DNS

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/wolf-joe/ts-dns)](https://github.com/wolf-joe/ts-dns/releases)
[![Build Status](https://travis-ci.org/wolf-joe/ts-dns.svg?branch=master)](https://travis-ci.org/wolf-joe/ts-dns)
[![codecov](https://codecov.io/gh/wolf-joe/ts-dns/branch/master/graph/badge.svg)](https://codecov.io/gh/wolf-joe/ts-dns)
[![Go Report Card](https://goreportcard.com/badge/github.com/wolf-joe/ts-dns)](https://goreportcard.com/report/github.com/wolf-joe/ts-dns)
![GitHub](https://img.shields.io/github/license/wolf-joe/ts-dns)

> 简单易用的DNS分组/转发器

## 基本特性

* 默认基于`CN IP列表` + `GFWList`进行域名分组；
* 支持DNS over UDP/TCP/TLS/HTTPS、非标准端口DNS；
* 支持选择ping值最低的IPv4地址（tcp/icmp ping）；
* 支持并发请求/socks5代理请求上游DNS，支持附带指定ECS信息；
* 支持多Hosts文件 + 自定义Hosts、通配符Hosts；
* 支持配置文件自动重载，支持监听TCP/UDP端口；
* 支持DNS查询缓存（IP乱序、TTL倒计时、ECS）；
* 支持屏蔽指定查询类型；
* 支持将查询结果中的IPv4地址添加至IPSet。

## DNS查询请求处理流程

1. 当域名匹配指定规则（配置文件里各组的`rules`）时，将请求转发至对应组上游DNS并直接返回；
2. 如未匹配规则，则假设域名为`clean`组，向`clean`组的上游DNS转发查询请求，并做如下判断：
   * 如果查询结果中所有IPv4地址均为`CN IP`，则直接返回；
   * 如果查询结果中出现非`CN IP`，进一步判断：
      * 如果该域名匹配GFWList列表，则向`dirty`组的上游DNS转发查询请求并返回；
      * 否则返回查询结果。

## 使用说明

1. 在[Releases页面](https://github.com/wolf-joe/ts-dns/releases)下载对应系统和平台的压缩包；
2. 解压后按需求编辑配置文件`ts-dns.toml`（可选）并运行进程：
  ```shell
  # ./ts-dns -h  # 显示命令行帮助信息
  # ./ts-dns -c ts-dns.toml  # 指定配置文件名
  # ./ts-dns -r  # 自动重载配置文件
  ./ts-dns
  ```

## 配置示例

> 完整配置文件参见`ts-dns.full.toml`

1. 默认配置（`ts-dns.toml`），开箱即用
  ```toml
  listen = ":53"
  gfwlist = "gfwlist.txt"
  cnip = "cnip.txt"

  [groups]
    [groups.clean]
    dns = ["223.5.5.5", "114.114.114.114"]
    concurrent = true

    [groups.dirty]
    dns = [""]  # 省略
  ```

2. 选择ping值最低的IPv4地址（启用时建议以root权限运行本程序）
  ```toml
  # ...
  [groups.clean]
    dns = ["223.5.5.5", "114.114.114.114"]
    fastest_v4 = true
  # ...
  ```

3. 指定hosts文件和自定义hosts
  ```toml
  # ...
  hosts_files = ["adaway.txt"]
  [hosts]
  "www.example.com" = "1.1.1.1"
  # ...
  ```

4. 使用socks5代理转发DNS请求
  ```toml
  # ...
    [groups.dirty]
    socks5 = "127.0.0.1:1080"
    # ...
  ```

5. 转发至上游DNS时默认附带指定ECS信息（暂不支持DOH）
  ```toml
  # ...
    [groups.clean]
    ecs = "1.2.4.0/24"
    # ...
  ```

6. 自定义域名分组
  ```toml
  # ...
    [groups.work]
    dns = ["10.1.1.1"]
    rules = ["company.com"]
    # ...
  ```

7. 动态添加IPSet记录（使用前请阅读`ts-dns.full.toml`对应说明）
  ```toml
  # ...
    [groups.dirty]
    ipset = "blocked"
    ipset_ttl = 86400
    # ...
  ```


## TODO

* 设置fallback DNS

## 特别鸣谢
* [github.com/arloan/prdns](https://github.com/arloan/prdns)
* [github.com/gfwlist/gfwlist](https://github.com/gfwlist/gfwlist)
