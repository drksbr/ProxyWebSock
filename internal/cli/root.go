package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/drksbr/ProxyWebSock/internal/agent"
	"github.com/drksbr/ProxyWebSock/internal/relay"
	"github.com/drksbr/ProxyWebSock/internal/runtime"
	"github.com/drksbr/ProxyWebSock/internal/version"
)

func Execute() error {
	opts := &runtime.Options{
		LogLevel: "info",
	}
	cmd := newRootCommand(opts)
	return cmd.Execute()
}

func newRootCommand(opts *runtime.Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "intratun",
		Short:        "HTTP CONNECT proxy over WebSocket reverse tunnel",
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.SetupLogger()
		},
	}

	cmd.PersistentFlags().BoolVar(&opts.JSONLogs, "json-logs", false, "emit logs in JSON format")
	cmd.PersistentFlags().StringVar(&opts.LogLevel, "log-level", opts.LogLevel, "log level (debug, info, warn, error)")

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
