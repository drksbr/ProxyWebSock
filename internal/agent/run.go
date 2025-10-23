package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/drksbr/ProxyWebSock/internal/version"
)

type agent struct {
	opts   *options
	logger *slog.Logger
	rngMu  sync.Mutex
	rng    *rand.Rand
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
			delay := a.jitter(backoff)
			a.logger.Warn("connection failed", "error", err, "retry_in", delay.String())
		} else {
			a.logger.Info("connection terminated, reconnecting")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(start) > time.Minute {
			backoff = a.opts.reconnectMin
		}
		sleep := a.jitter(backoff)
		select {
		case <-time.After(sleep):
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

func (a *agent) jitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	a.rngMu.Lock()
	if a.rng == nil {
		a.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	f := 0.4
	min := 1 - f/2
	max := 1 + f/2
	scale := min + a.rng.Float64()*(max-min)
	a.rngMu.Unlock()
	return time.Duration(float64(base) * scale)
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
