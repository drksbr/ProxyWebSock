package relay

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/drksbr/ProxyWebSock/internal/runtime"
)

type relayOptions struct {
	proxyListen      string
	secureListen     string
	socksListen      string
	agentConfig      string
	aclPatterns      []string
	maxFrame         int
	maxInFlight      int
	streamQueueDepth int
	wsIdle           time.Duration
	dialTimeoutMs    int
	acmeHosts        []string
	acmeEmail        string
	acmeCache        string
	acmeHTTPAddr     string
	streamIDMode     string
}

type relayCounters struct {
	bytesUp      atomic.Int64
	bytesDown    atomic.Int64
	dialErrors   atomic.Int64
	authFailures atomic.Int64
}

func NewCommand(globals *runtime.Options) *cobra.Command {
	opts := &relayOptions{
		proxyListen:      ":8080",
		secureListen:     ":8443",
		socksListen:      "",
		maxFrame:         32 * 1024,
		maxInFlight:      256 * 1024,
		streamQueueDepth: 128,
		wsIdle:           45 * time.Second,
		dialTimeoutMs:    10000,
		acmeHTTPAddr:     "",
		streamIDMode:     "uuid",
	}

	cmd := &cobra.Command{
		Use:   "relay",
		Short: "Public relay accepting agents and proxying HTTP CONNECT",
		RunE: func(cmd *cobra.Command, args []string) error {
			if globals.Logger() == nil {
				if err := globals.SetupLogger(); err != nil {
					return err
				}
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			server, err := newRelayServer(globals.Logger().With("component", "relay"), opts)
			if err != nil {
				return err
			}
			return server.run(ctx)
		},
	}

	cmd.Flags().StringVar(&opts.proxyListen, "proxy-listen", opts.proxyListen, "listen address for HTTP CONNECT proxy (plain HTTP)")
	cmd.Flags().StringVar(&opts.secureListen, "secure-listen", opts.secureListen, "listen address for TLS endpoints (/tunnel, /, /metrics)")
	cmd.Flags().StringVar(&opts.socksListen, "socks-listen", opts.socksListen, "optional listen address for SOCKS5 proxy (plain TCP)")
	cmd.Flags().StringVar(&opts.agentConfig, "agent-config", "", "path to YAML file containing agent definitions")
	cmd.Flags().StringSliceVar(&opts.aclPatterns, "acl-allow", nil, "regex ACLs for allowed host:port destinations (repeatable)")
	cmd.Flags().IntVar(&opts.maxFrame, "max-frame", opts.maxFrame, "maximum payload size per frame in bytes")
	cmd.Flags().IntVar(&opts.maxInFlight, "max-inflight", opts.maxInFlight, "maximum queued bytes per stream when sending to clients (0 disables)")
	cmd.Flags().IntVar(&opts.streamQueueDepth, "stream-queue-depth", opts.streamQueueDepth, "depth of relay per-stream client write queues")
	cmd.Flags().DurationVar(&opts.wsIdle, "ws-idle", opts.wsIdle, "maximum idle time on agent websocket before disconnect")
	cmd.Flags().IntVar(&opts.dialTimeoutMs, "dial-timeout-ms", opts.dialTimeoutMs, "timeout in milliseconds for agent dial acknowledgment (0 disables)")
	cmd.Flags().StringSliceVar(&opts.acmeHosts, "acme-host", nil, "hostnames for Let's Encrypt certificates (repeatable)")
	cmd.Flags().StringVar(&opts.acmeEmail, "acme-email", "", "contact email for Let's Encrypt registration")
	cmd.Flags().StringVar(&opts.acmeCache, "acme-cache", "", "directory for ACME certificate cache")
	cmd.Flags().StringVar(&opts.acmeHTTPAddr, "acme-http", opts.acmeHTTPAddr, "optional listen address for ACME HTTP-01 challenges (e.g. :80)")
	cmd.Flags().StringVar(&opts.streamIDMode, "stream-id-mode", opts.streamIDMode, "stream identifier generator (uuid or cuid)")

	return cmd
}
