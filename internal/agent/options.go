package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/spf13/cobra"

	"github.com/drksbr/ProxyWebSock/internal/runtime"
)

type options struct {
	relayURL      string
	agentID       string
	token         string
	dialTimeoutMs int
	readBuffer    int
	writeBuffer   int
	maxFrame      int
	maxInFlight   int
	queueDepth    int
	reconnectMin  time.Duration
	reconnectMax  time.Duration
	relayParsed   *url.URL
	logger        *slog.Logger
}

func NewCommand(globals *runtime.Options) *cobra.Command {
	opts := &options{
		dialTimeoutMs: 5000,
		readBuffer:    64 * 1024,
		writeBuffer:   64 * 1024,
		maxFrame:      32 * 1024,
		maxInFlight:   256 * 1024,
		queueDepth:    128,
		reconnectMin:  2 * time.Second,
		reconnectMax:  30 * time.Second,
	}

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Agent that originates tunnels from inside the intranet",
		RunE: func(cmd *cobra.Command, args []string) error {
			if globals.Logger() == nil {
				if err := globals.SetupLogger(); err != nil {
					return err
				}
			}
			if err := opts.validate(); err != nil {
				return err
			}
			opts.logger = globals.Logger().With("component", "agent")
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return opts.run(ctx)
		},
	}

	cmd.Flags().StringVar(&opts.relayURL, "relay", "", "relay websocket endpoint (wss://host/tunnel)")
	cmd.Flags().StringVar(&opts.agentID, "id", "", "agent identifier")
	cmd.Flags().StringVar(&opts.token, "token", "", "agent shared token")
	cmd.Flags().IntVar(&opts.dialTimeoutMs, "dial-timeout-ms", opts.dialTimeoutMs, "timeout in milliseconds for dialing internal targets")
	cmd.Flags().IntVar(&opts.readBuffer, "read-buf", opts.readBuffer, "TCP read buffer size per stream")
	cmd.Flags().IntVar(&opts.writeBuffer, "write-buf", opts.writeBuffer, "websocket write buffer size")
	cmd.Flags().IntVar(&opts.maxFrame, "max-frame", opts.maxFrame, "maximum payload size per frame in bytes")
	cmd.Flags().IntVar(&opts.maxInFlight, "max-inflight", opts.maxInFlight, "maximum unacknowledged bytes per stream (0 disables)")
	cmd.Flags().IntVar(&opts.queueDepth, "stream-queue-depth", opts.queueDepth, "depth of per-stream inbound queue buffers")

	return cmd
}

func (o *options) validate() error {
	if o.relayURL == "" {
		return errors.New("--relay is required")
	}
	parsed, err := url.Parse(o.relayURL)
	if err != nil {
		return fmt.Errorf("invalid relay url: %w", err)
	}
	if parsed.Scheme != "wss" && parsed.Scheme != "ws" {
		return errors.New("relay url must use ws or wss scheme")
	}
	if parsed.Host == "" {
		return errors.New("relay url missing host")
	}
	o.relayParsed = parsed

	if o.agentID == "" || o.token == "" {
		return errors.New("--id and --token are required")
	}
	if o.maxFrame <= 0 {
		return errors.New("--max-frame must be positive")
	}
	if o.readBuffer <= 0 || o.writeBuffer <= 0 {
		return errors.New("buffers must be positive")
	}
	if o.queueDepth <= 0 {
		return errors.New("--stream-queue-depth must be positive")
	}
	if o.reconnectMin <= 0 {
		o.reconnectMin = 2 * time.Second
	}
	if o.reconnectMax < o.reconnectMin {
		o.reconnectMax = o.reconnectMin
	}
	return nil
}
