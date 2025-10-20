package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	version = "0.1.0"
)

func main() {
	root := newRootCommand()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	opts := &globalOptions{}

	cmd := &cobra.Command{
		Use:          "intratun",
		Short:        "HTTP CONNECT proxy over WebSocket reverse tunnel",
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.setupLogger()
		},
	}

	cmd.PersistentFlags().BoolVar(&opts.jsonLogs, "json-logs", false, "emit logs in JSON format")
	cmd.PersistentFlags().StringVar(&opts.logLevel, "log-level", "info", "log level (debug, info, warn, error)")

	cmd.AddCommand(newRelayCommand(opts))
	cmd.AddCommand(newAgentCommand(opts))
	cmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", version)
		},
	})

	return cmd
}

type globalOptions struct {
	jsonLogs bool
	logLevel string
	logger   *slog.Logger
}

func (g *globalOptions) setupLogger() error {
	level := slog.LevelInfo
	switch g.logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return fmt.Errorf("unknown log level %q", g.logLevel)
	}

	var handler slog.Handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	if g.jsonLogs {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}

	g.logger = slog.New(handler)
	return nil
}

func withSignalContext(parent context.Context) context.Context {
	ctx, cancel := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ctx
}
