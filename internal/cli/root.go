package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/drksbr/ProxyWebSock/internal/agent"
	"github.com/drksbr/ProxyWebSock/internal/relay"
	"github.com/drksbr/ProxyWebSock/internal/runtime"
	"github.com/drksbr/ProxyWebSock/internal/util"
	"github.com/drksbr/ProxyWebSock/internal/version"
)

func Execute() error {
	opts := &runtime.Options{
		LogLevel: "info",
	}
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
			return opts.SetupPIDFile()
		},
	}

	cmd.PersistentFlags().BoolVar(&opts.JSONLogs, "json-logs", false, "emit logs in JSON format")
	cmd.PersistentFlags().StringVar(&opts.LogLevel, "log-level", opts.LogLevel, "log level (debug, info, warn, error)")
	cmd.PersistentFlags().StringVar(&opts.PIDFile, "pid-file", "", "write PID to file and remove it on exit")

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
