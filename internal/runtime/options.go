package runtime

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type Options struct {
	JSONLogs bool
	LogLevel string
	PIDFile  string

	logger      *slog.Logger
	cleanupFns  []func()
	pidFileOnce bool
}

func (o *Options) SetupLogger() error {
	level := slog.LevelInfo
	switch o.LogLevel {
	case "", "info":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return fmt.Errorf("unknown log level %q", o.LogLevel)
	}

	var handler slog.Handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	if o.JSONLogs {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	o.logger = slog.New(handler)
	return nil
}

func (o *Options) Logger() *slog.Logger {
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
