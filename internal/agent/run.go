package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/drksbr/ProxyWebSock/internal/version"
)

type agent struct {
	opts   *options
	logger *slog.Logger
}

func (o *options) run(ctx context.Context) error {
	a := &agent{
		opts:   o,
		logger: o.logger,
	}
	return a.run(ctx)
}

func (a *agent) run(ctx context.Context) error {
	backoff := a.opts.reconnectMin
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		start := time.Now()
		err := a.connectOnce(ctx)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if err != nil {
			a.logger.Warn("connection failed", "error", err)
		} else {
			a.logger.Info("connection terminated, reconnecting")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(start) > time.Minute {
			backoff = a.opts.reconnectMin
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		if backoff < a.opts.reconnectMax {
			backoff *= 2
			if backoff > a.opts.reconnectMax {
				backoff = a.opts.reconnectMax
			}
		}
	}
}

func (a *agent) connectOnce(ctx context.Context) error {
	dialer := websocket.Dialer{
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  15 * time.Second,
		EnableCompression: false,
		ReadBufferSize:    a.opts.readBuffer,
		WriteBufferSize:   a.opts.writeBuffer,
	}
	if a.opts.relayParsed.Scheme == "wss" {
		dialer.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: a.opts.relayParsed.Hostname(),
		}
	}

	header := http.Header{
		"User-Agent": {fmt.Sprintf("intratun-agent/%s", version.Version)},
	}

	conn, resp, err := dialer.DialContext(ctx, a.opts.relayURL, header)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return err
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}

	session := newSession(a, conn)
	return session.run(ctx)
}
