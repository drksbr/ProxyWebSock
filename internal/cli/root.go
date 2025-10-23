package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/drksbr/ProxyWebSock/internal/agent"
	"github.com/drksbr/ProxyWebSock/internal/config"
	"github.com/drksbr/ProxyWebSock/internal/relay"
	"github.com/drksbr/ProxyWebSock/internal/runtime"
	"github.com/drksbr/ProxyWebSock/internal/util"
	"github.com/drksbr/ProxyWebSock/internal/version"
)

func Execute() error {
	opts := &runtime.Options{
		LogLevel: "info",
		Service:  "intratun",
	}
	if env := os.Getenv("INTRATUN_ENV"); env != "" {
		opts.Env = env
	}
	opts.JSONLogs = config.GetBoolEnv("INTRATUN_JSON_LOGS", opts.JSONLogs)
	opts.LogLevel = config.GetStringEnv("INTRATUN_LOG_LEVEL", opts.LogLevel)
	opts.PIDFile = config.GetStringEnv("INTRATUN_PID_FILE", opts.PIDFile)
	opts.Service = config.GetStringEnv("INTRATUN_SERVICE_NAME", opts.Service)
	opts.TraceEnabled = config.GetBoolEnv("INTRATUN_TRACE_ENABLED", opts.TraceEnabled)
	opts.TraceExporter = config.GetStringEnv("INTRATUN_TRACE_EXPORTER", opts.TraceExporter)
	opts.TraceEndpoint = config.GetStringEnv("INTRATUN_TRACE_ENDPOINT", opts.TraceEndpoint)
	opts.TraceInsecure = config.GetBoolEnv("INTRATUN_TRACE_INSECURE", opts.TraceInsecure)
	rootCtx, cancel := util.WithSignalContext(context.Background())
	defer cancel()
	defer opts.Cleanup()

	cmd := newRootCommand(opts)
	cmd.SetContext(rootCtx)
	return cmd.ExecuteContext(rootCtx)
}

func newRootCommand(opts *runtime.Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "intratun",
		Short:        "HTTP CONNECT proxy over WebSocket reverse tunnel",
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.SetupLogger(); err != nil {
				return err
			}
			if err := opts.SetupTracing(cmd.Context()); err != nil {
				return err
			}
			return opts.SetupPIDFile()
		},
	}

	cmd.PersistentFlags().BoolVar(&opts.JSONLogs, "json-logs", false, "emit logs in JSON format")
	cmd.PersistentFlags().StringVar(&opts.LogLevel, "log-level", opts.LogLevel, "log level (debug, info, warn, error)")
	cmd.PersistentFlags().StringVar(&opts.PIDFile, "pid-file", "", "write PID to file and remove it on exit")
	cmd.PersistentFlags().BoolVar(&opts.TraceEnabled, "trace-enabled", opts.TraceEnabled, "enable OpenTelemetry traces")
	cmd.PersistentFlags().StringVar(&opts.TraceExporter, "trace-exporter", opts.TraceExporter, "trace exporter (stdout, otlp-grpc, otlp-http)")
	cmd.PersistentFlags().StringVar(&opts.TraceEndpoint, "trace-endpoint", opts.TraceEndpoint, "trace exporter endpoint (host:port or URL)")
	cmd.PersistentFlags().BoolVar(&opts.TraceInsecure, "trace-insecure", opts.TraceInsecure, "disable TLS when exporting traces")

	cmd.AddCommand(relay.NewCommand(opts))
	cmd.AddCommand(agent.NewCommand(opts))
	cmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.Version)
		},
	})

	return cmd
}
