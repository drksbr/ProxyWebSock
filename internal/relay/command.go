package relay

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/drksbr/ProxyWebSock/internal/config"
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
	configFile       string
}

type relayFileConfig struct {
	ProxyListen      string        `yaml:"proxy_listen"`
	SecureListen     string        `yaml:"secure_listen"`
	SocksListen      string        `yaml:"socks_listen"`
	AgentConfig      string        `yaml:"agent_config"`
	ACLPatterns      []string      `yaml:"acl_allow"`
	MaxFrame         int           `yaml:"max_frame"`
	MaxInFlight      int           `yaml:"max_inflight"`
	StreamQueueDepth int           `yaml:"stream_queue_depth"`
	WSIdle           time.Duration `yaml:"ws_idle"`
	DialTimeoutMs    int           `yaml:"dial_timeout_ms"`
	ACMEHosts        []string      `yaml:"acme_hosts"`
	ACMEEmail        string        `yaml:"acme_email"`
	ACMECache        string        `yaml:"acme_cache"`
	ACMEHTTP         string        `yaml:"acme_http"`
	StreamIDMode     string        `yaml:"stream_id_mode"`
}

type relayCounters struct {
	bytesUp      atomic.Int64
	bytesDown    atomic.Int64
	dialErrors   atomic.Int64
	authFailures atomic.Int64
}

func (o *relayOptions) loadConfiguration() error {
	if o == nil {
		return nil
	}
	configPath := o.configFile
	if configPath == "" {
		configPath = os.Getenv("INTRATUN_RELAY_CONFIG")
	}
	var fileCfg relayFileConfig
	if err := config.LoadYAML(configPath, &fileCfg); err != nil {
		return err
	}
	o.applyFileConfig(fileCfg)
	o.applyEnvOverrides()
	return nil
}

func (o *relayOptions) applyFileConfig(cfg relayFileConfig) {
	if cfg.ProxyListen != "" {
		o.proxyListen = cfg.ProxyListen
	}
	if cfg.SecureListen != "" {
		o.secureListen = cfg.SecureListen
	}
	if cfg.SocksListen != "" {
		o.socksListen = cfg.SocksListen
	}
	if cfg.AgentConfig != "" {
		o.agentConfig = cfg.AgentConfig
	}
	if len(cfg.ACLPatterns) > 0 {
		o.aclPatterns = append([]string(nil), cfg.ACLPatterns...)
	}
	if cfg.MaxFrame > 0 {
		o.maxFrame = cfg.MaxFrame
	}
	if cfg.MaxInFlight >= 0 {
		o.maxInFlight = cfg.MaxInFlight
	}
	if cfg.StreamQueueDepth > 0 {
		o.streamQueueDepth = cfg.StreamQueueDepth
	}
	if cfg.WSIdle > 0 {
		o.wsIdle = cfg.WSIdle
	}
	if cfg.DialTimeoutMs > 0 {
		o.dialTimeoutMs = cfg.DialTimeoutMs
	}
	if len(cfg.ACMEHosts) > 0 {
		o.acmeHosts = append([]string(nil), cfg.ACMEHosts...)
	}
	if cfg.ACMEEmail != "" {
		o.acmeEmail = cfg.ACMEEmail
	}
	if cfg.ACMECache != "" {
		o.acmeCache = cfg.ACMECache
	}
	if cfg.ACMEHTTP != "" {
		o.acmeHTTPAddr = cfg.ACMEHTTP
	}
	if cfg.StreamIDMode != "" {
		o.streamIDMode = cfg.StreamIDMode
	}
}

func (o *relayOptions) applyEnvOverrides() {
	o.proxyListen = config.GetStringEnv("INTRATUN_RELAY_PROXY_LISTEN", o.proxyListen)
	o.secureListen = config.GetStringEnv("INTRATUN_RELAY_SECURE_LISTEN", o.secureListen)
	o.socksListen = config.GetStringEnv("INTRATUN_RELAY_SOCKS_LISTEN", o.socksListen)
	o.agentConfig = config.GetStringEnv("INTRATUN_RELAY_AGENT_CONFIG", o.agentConfig)
	if aclEnv := os.Getenv("INTRATUN_RELAY_ACL_ALLOW"); aclEnv != "" {
		o.aclPatterns = splitAndTrim(aclEnv)
	}
	o.maxFrame = config.GetIntEnv("INTRATUN_RELAY_MAX_FRAME", o.maxFrame)
	o.maxInFlight = config.GetIntEnv("INTRATUN_RELAY_MAX_INFLIGHT", o.maxInFlight)
	o.streamQueueDepth = config.GetIntEnv("INTRATUN_RELAY_STREAM_QUEUE_DEPTH", o.streamQueueDepth)
	o.wsIdle = config.GetDurationEnv("INTRATUN_RELAY_WS_IDLE", o.wsIdle)
	o.dialTimeoutMs = config.GetIntEnv("INTRATUN_RELAY_DIAL_TIMEOUT_MS", o.dialTimeoutMs)
	if hostsEnv := os.Getenv("INTRATUN_RELAY_ACME_HOSTS"); hostsEnv != "" {
		o.acmeHosts = splitAndTrim(hostsEnv)
	}
	o.acmeEmail = config.GetStringEnv("INTRATUN_RELAY_ACME_EMAIL", o.acmeEmail)
	o.acmeCache = config.GetStringEnv("INTRATUN_RELAY_ACME_CACHE", o.acmeCache)
	o.acmeHTTPAddr = config.GetStringEnv("INTRATUN_RELAY_ACME_HTTP", o.acmeHTTPAddr)
	o.streamIDMode = config.GetStringEnv("INTRATUN_RELAY_STREAM_ID_MODE", o.streamIDMode)
}

func NewCommand(globals *runtime.Options) *cobra.Command {
	opts := &relayOptions{
		proxyListen:      ":8080",
		secureListen:     ":8443",
		socksListen:      "",
		maxFrame:         32 * 1024,
		maxInFlight:      256 * 1024,
		streamQueueDepth: 1024,
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
			if err := opts.loadConfiguration(); err != nil {
				return err
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			baseLogger := globals.Logger()
			if baseLogger == nil {
				return fmt.Errorf("logger not initialised")
			}
			server, err := newRelayServer(baseLogger.WithComponent("relay"), opts)
			if err != nil {
				return err
			}
			return server.run(ctx)
		},
	}

	cmd.Flags().StringVar(&opts.configFile, "config", "", "path to relay YAML configuration file")
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

func splitAndTrim(input string) []string {
	if input == "" {
		return nil
	}
	parts := strings.FieldsFunc(input, func(r rune) bool {
		switch r {
		case ',', ';', ' ', '\n', '\t':
			return true
		default:
			return false
		}
	})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
