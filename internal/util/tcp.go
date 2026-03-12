package util

import (
	"net"
	"time"
)

// TuneTCPConn applies low-level socket tuning when the connection is TCP-based.
// The calls are best-effort because some platforms or wrapped conns may not support all knobs.
func TuneTCPConn(conn net.Conn, readBuffer, writeBuffer int) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok || tcpConn == nil {
		return
	}
	if readBuffer > 0 {
		_ = tcpConn.SetReadBuffer(readBuffer)
	}
	if writeBuffer > 0 {
		_ = tcpConn.SetWriteBuffer(writeBuffer)
	}
	_ = tcpConn.SetNoDelay(true)
	_ = tcpConn.SetKeepAlive(true)
	_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
}
