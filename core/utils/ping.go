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
