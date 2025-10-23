package logger

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
)

// Format defines the supported output formats for the logger.
type Format string

const (
	// FormatText renders logs in a human-readable text form.
	FormatText Format = "text"
	// FormatJSON renders logs as JSON objects.
	FormatJSON Format = "json"
)

// Config controls the behaviour of the structured logger.
type Config struct {
	Format      Format
	Level       string
	AddSource   bool
	Writer      io.Writer
	ServiceName string
	Environment string
	Version     string
}

// Logger wraps slog.Logger to attach standard attributes and context metadata.
type Logger struct {
	*slog.Logger
	cfg Config
}

// New constructs a new structured logger with the provided configuration.
func New(cfg Config) (*Logger, error) {
	level := slog.LevelInfo
	switch cfg.Level {
	case "", "info":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "err", "error":
		level = slog.LevelError
	default:
		return nil, errors.New("unsupported log level: " + cfg.Level)
	}

	if cfg.Writer == nil {
		cfg.Writer = os.Stdout
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "intratun"
	}

	handlerOpts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.AddSource,
	}

	var handler slog.Handler
	switch cfg.Format {
	case FormatJSON:
		handler = slog.NewJSONHandler(cfg.Writer, handlerOpts)
	case FormatText, "":
		handler = slog.NewTextHandler(cfg.Writer, handlerOpts)
	default:
		return nil, errors.New("unsupported log format: " + string(cfg.Format))
	}

	handler = &contextHandler{Handler: handler}

	logger := slog.New(handler).With(
		slog.Int("pid", os.Getpid()),
		slog.String("service", cfg.ServiceName),
	)
	if cfg.Environment != "" {
		logger = logger.With(slog.String("env", cfg.Environment))
	}
	if cfg.Version != "" {
		logger = logger.With(slog.String("version", cfg.Version))
	}

	return &Logger{
		Logger: logger,
		cfg:    cfg,
	}, nil
}

// WithComponent returns a child logger tagged with the provided component name.
func (l *Logger) WithComponent(component string) *slog.Logger {
	if l == nil || l.Logger == nil || component == "" {
		if l == nil {
			return nil
		}
		return l.Logger
	}
	return l.Logger.With(slog.String("component", component))
}

// WithContext decorates the logger with trace/span information extracted from the context.
func (l *Logger) WithContext(ctx context.Context) *slog.Logger {
	if l == nil || l.Logger == nil {
		return nil
	}
	traceID := TraceIDFromContext(ctx)
	spanID := SpanIDFromContext(ctx)

	logger := l.Logger
	if traceID != "" {
		logger = logger.With(slog.String("trace_id", traceID))
	}
	if spanID != "" {
		logger = logger.With(slog.String("span_id", spanID))
	}
	return logger
}

type contextHandler struct {
	slog.Handler
}

func (h *contextHandler) Handle(ctx context.Context, record slog.Record) error {
	if traceID := TraceIDFromContext(ctx); traceID != "" {
		record.AddAttrs(slog.String("trace_id", traceID))
	}
	if spanID := SpanIDFromContext(ctx); spanID != "" {
		record.AddAttrs(slog.String("span_id", spanID))
	}
	return h.Handler.Handle(ctx, record)
}
