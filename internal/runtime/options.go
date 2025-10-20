package runtime

import (
	"fmt"
	"log/slog"
	"os"
)

type Options struct {
	JSONLogs bool
	LogLevel string

	logger *slog.Logger
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
