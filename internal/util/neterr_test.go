package util

import (
	"errors"
	"io"
	"net"
	"testing"
)

func TestIsExpectedNetClose(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "eof", err: io.EOF, want: true},
		{name: "net closed", err: net.ErrClosed, want: true},
		{name: "closed connection text", err: errors.New("read tcp 1.2.3.4:1234->5.6.7.8:443: use of closed network connection"), want: true},
		{name: "windows wsarecv", err: errors.New("wsarecv: Foi forçado o cancelamento de uma conexão existente pelo host remoto."), want: true},
		{name: "reset by peer", err: errors.New("read tcp: connection reset by peer"), want: true},
		{name: "timeout", err: errors.New("i/o timeout"), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsExpectedNetClose(tc.err); got != tc.want {
				t.Fatalf("IsExpectedNetClose() = %v, want %v", got, tc.want)
			}
		})
	}
}
