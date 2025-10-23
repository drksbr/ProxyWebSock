package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/drksbr/ProxyWebSock/internal/logger"
	"github.com/drksbr/ProxyWebSock/internal/observability"
	"github.com/drksbr/ProxyWebSock/internal/version"
)

type Options struct {
	JSONLogs      bool
	LogLevel      string
	PIDFile       string
	Service       string
	Env           string
	TraceEnabled  bool
	TraceExporter string
	TraceEndpoint string
	TraceInsecure bool

	logger        *logger.Logger
	cleanupFns    []func()
	pidFileOnce   bool
	traceShutdown func(context.Context) error
}

func (o *Options) SetupLogger() error {
	if o.logger != nil {
		return nil
	}
	cfg := logger.Config{
		Level:       o.LogLevel,
		Format:      logger.FormatText,
		ServiceName: o.Service,
		Environment: o.Env,
		Version:     version.Version,
	}
	if o.JSONLogs {
		cfg.Format = logger.FormatJSON
	}
	lg, err := logger.New(cfg)
	if err != nil {
		return err
	}
	o.logger = lg
	return nil
}

func (o *Options) Logger() *logger.Logger {
	return o.logger
}

func (o *Options) SetupPIDFile() error {
	if o.PIDFile == "" || o.pidFileOnce {
		return nil
	}

	dir := filepath.Dir(o.PIDFile)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create pid directory: %w", err)
		}
	}

	if existing, err := os.ReadFile(o.PIDFile); err == nil {
		if pid, parseErr := strconv.Atoi(strings.TrimSpace(string(existing))); parseErr == nil && pid > 0 {
			if proc, findErr := os.FindProcess(pid); findErr == nil {
				if sigErr := proc.Signal(syscall.Signal(0)); sigErr == nil {
					return fmt.Errorf("pid file %q already in use by running process %d", o.PIDFile, pid)
				}
			}
		}
	}

	content := strconv.Itoa(os.Getpid()) + "\n"
	if err := os.WriteFile(o.PIDFile, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}

	o.pidFileOnce = true
	o.RegisterCleanup(func() {
		if err := os.Remove(o.PIDFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			if o.logger != nil {
				o.logger.Warn("remove pid file", "error", err, "path", o.PIDFile)
			}
		}
	})

	return nil
}

func (o *Options) RegisterCleanup(fn func()) {
	if fn == nil {
		return
	}
	o.cleanupFns = append(o.cleanupFns, fn)
}

func (o *Options) Cleanup() {
	for i := len(o.cleanupFns) - 1; i >= 0; i-- {
		if o.cleanupFns[i] != nil {
			o.cleanupFns[i]()
		}
	}
	o.cleanupFns = nil
}

func (o *Options) SetupTracing(ctx context.Context) error {
	if !o.TraceEnabled {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	shutdown, err := observability.InitTracing(ctx, observability.TracingConfig{
		Enabled:     o.TraceEnabled,
		Exporter:    o.TraceExporter,
		ServiceName: o.Service,
		Environment: o.Env,
		Endpoint:    o.TraceEndpoint,
		Insecure:    o.TraceInsecure,
	})
	if err != nil {
		return err
	}
	shutdownFunc := shutdown
	o.RegisterCleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := shutdownFunc(shutdownCtx); shutdownErr != nil && o.logger != nil {
			o.logger.Warn("trace shutdown", "error", shutdownErr)
		}
	})
	return nil
}
