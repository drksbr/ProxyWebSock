package observability

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// TracingConfig describes tracing exporter settings.
type TracingConfig struct {
	Enabled     bool
	Exporter    string
	ServiceName string
	Environment string
	Endpoint    string
	Insecure    bool
}

// InitTracing sets up the global OpenTelemetry tracer provider based on the configuration.
// The returned shutdown function must be called during program termination.
func InitTracing(ctx context.Context, cfg TracingConfig) (func(context.Context) error, error) {
	if !cfg.Enabled {
		return func(context.Context) error { return nil }, nil
	}
	var (
		exporter sdktrace.SpanExporter
		err      error
	)
	switch strings.ToLower(cfg.Exporter) {
	case "", "stdout":
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
	case "otlp", "otlp-grpc", "otlp_grpc":
		endpoint := firstNonEmpty(cfg.Endpoint, os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
		clientOpts := []otlptracegrpc.Option{}
		if endpoint != "" {
			clientOpts = append(clientOpts, otlptracegrpc.WithEndpoint(endpoint))
		}
		if cfg.Insecure {
			clientOpts = append(clientOpts, otlptracegrpc.WithInsecure())
		}
		exporter, err = otlptracegrpc.New(ctx, clientOpts...)
	case "otlp-http", "otlp_http", "otlpthttp":
		endpoint := firstNonEmpty(cfg.Endpoint, os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
		if endpoint == "" {
			endpoint = "http://localhost:4318"
		}
		clientOpts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
		if cfg.Insecure {
			clientOpts = append(clientOpts, otlptracehttp.WithInsecure())
		}
		exporter, err = otlptracehttp.New(ctx, clientOpts...)
	default:
		err = fmt.Errorf("unsupported tracing exporter %q", cfg.Exporter)
	}
	if err != nil {
		return nil, err
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(valueOrFallback(cfg.ServiceName, "intratun")),
			semconv.DeploymentEnvironmentKey.String(valueOrFallback(cfg.Environment, os.Getenv("INTRATUN_ENV"))),
		),
	)
	if err != nil {
		return nil, err
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

func valueOrFallback(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
