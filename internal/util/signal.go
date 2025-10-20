package util

import (
	"context"
	"os/signal"
	"syscall"
)

func WithSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
}
