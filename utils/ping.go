package utils

import (
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/sparrc/go-ping"
)

// PingIP 向指定ip地址发起icmp ping/tcp ping（如tcpPort大于0），返回值为nil代表ping成功
func PingIP(ipAddr string, tcpPort int, timeout time.Duration) error {
	if tcpPort > 0 { // tcp ping
		addr := ipAddr + ":" + strconv.Itoa(tcpPort)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return err
		}
		_ = conn.Close()
		return nil
	}
	// icmp ping
	task, err := ping.NewPinger(ipAddr)
	if err != nil {
		return err
	}
	task.Count, task.Timeout = 1, timeout
	task.SetPrivileged(true)
	task.Run()
	if stat := task.Statistics(); stat.PacketsRecv >= 1 {
		return nil
	}
	return errors.New("package loss")
}

// FastestPingIP 向指定IP地址列表同时发起ping，返回ping值最低的IP地址和耗时
func FastestPingIP(ipAddr []string, tcpPort int, timeout time.Duration,
) (string, int64, error) {
	pingDone := make(chan string, len(ipAddr))
	begin := time.Now()
	for _, ip := range ipAddr {
		go func(addr string) {
			if err := PingIP(addr, tcpPort, timeout); err == nil {
				pingDone <- addr
			}
		}(ip)
	}
	var fastestIP string // 第一个从chan返回的地址就是ping值最低的地址
	select {
	case fastestIP = <-pingDone:
	case <-time.After(timeout):
	}
	if fastestIP == "" {
		return "", 0, errors.New("timeout")
	}
	cost := time.Now().Sub(begin).Milliseconds()
	return fastestIP, cost, nil
}
