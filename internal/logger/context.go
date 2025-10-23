package logger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

type contextKey string

const (
	traceIDKey contextKey = "logger-trace-id"
	spanIDKey  contextKey = "logger-span-id"
)

// ContextWithTrace stores the provided trace ID in the context.
func ContextWithTrace(ctx context.Context, traceID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, traceIDKey, traceID)
}

// ContextWithSpan stores the provided span ID in the context.
func ContextWithSpan(ctx context.Context, spanID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, spanIDKey, spanID)
}

// TraceIDFromContext extracts the trace ID from the context if present.
func TraceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(traceIDKey).(string); ok {
		return v
	}
	return ""
}

// SpanIDFromContext extracts the span ID from the context if present.
func SpanIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(spanIDKey).(string); ok {
		return v
	}
	return ""
}

// WithTraceAndSpan decorates the context with freshly generated trace and span identifiers.
func WithTraceAndSpan(ctx context.Context) (context.Context, string, string) {
	traceID := NewTraceID()
	spanID := NewSpanID()
	ctx = ContextWithTrace(ctx, traceID)
	ctx = ContextWithSpan(ctx, spanID)
	return ctx, traceID, spanID
}

// NewTraceID returns a random 16-byte hex encoded identifier suitable for tracing.
func NewTraceID() string {
	return randomHex(16)
}

// NewSpanID returns a random 8-byte hex encoded identifier suitable for spans.
func NewSpanID() string {
	return randomHex(8)
}

func randomHex(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}
