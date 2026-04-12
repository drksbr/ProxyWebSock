package util

import (
	"errors"
	"io"
	"net"
	"strings"
)

// IsExpectedNetClose reports whether err represents a connection shutdown that
// is expected during normal stream teardown or peer disconnects.
func IsExpectedNetClose(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}

	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "use of closed network connection"):
		return true
	case strings.Contains(message, "broken pipe"):
		return true
	case strings.Contains(message, "connection reset by peer"):
		return true
	case strings.Contains(message, "forcibly closed by the remote host"):
		return true
	case strings.Contains(message, "foi forçado o cancelamento de uma conexão existente pelo host remoto"):
		return true
	case strings.Contains(message, "software caused connection abort"):
		return true
	case strings.Contains(message, "connection aborted"):
		return true
	default:
		return false
	}
}
