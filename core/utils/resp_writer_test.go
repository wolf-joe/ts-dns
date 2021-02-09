package utils

import "testing"

func TestFakeRespWriter(t *testing.T) {
	writer := NewFakeRespWriter()
	_ = writer.WriteMsg(nil)
	_, _ = writer.Write(nil)
	writer.LocalAddr()
	writer.RemoteAddr()
	_ = writer.Close()
	_ = writer.TsigStatus()
	writer.TsigTimersOnly(true)
	writer.Hijack()
}
