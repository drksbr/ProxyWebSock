package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/drksbr/ProxyWebSock/internal/config"
	runtimecfg "github.com/drksbr/ProxyWebSock/internal/runtime"
)

type options struct {
	relayURL        string
	agentID         string
	token           string
	dialTimeoutMs   int
	dnsCacheTTL     time.Duration
	dnsNegativeTTL  time.Duration
	dnsStaleTTL     time.Duration
	dnsRefreshAhead time.Duration
	readBuffer      int
	writeBuffer     int
	maxFrame        int
	maxInFlight     int
	queueDepth      int
	reconnectMin    time.Duration
	reconnectMax    time.Duration
	updateManifest  string
	updateInterval  time.Duration
	updateTimeout   time.Duration
	relayParsed     *url.URL
	updateParsedURL *url.URL
	logger          *slog.Logger
	configFile      string
}

type agentFileConfig struct {
	Relay           string        `yaml:"relay"`
	ID              string        `yaml:"id"`
	Token           string        `yaml:"token"`
	DialTimeout     int           `yaml:"dial_timeout_ms"`
	DNSCacheTTL     time.Duration `yaml:"dns_cache_ttl"`
	DNSNegativeTTL  time.Duration `yaml:"dns_negative_ttl"`
	DNSStaleTTL     time.Duration `yaml:"dns_stale_ttl"`
	DNSRefreshAhead time.Duration `yaml:"dns_refresh_ahead"`
	ReadBuffer      int           `yaml:"read_buffer"`
	WriteBuffer     int           `yaml:"write_buffer"`
	MaxFrame        int           `yaml:"max_frame"`
	MaxInFlight     int           `yaml:"max_inflight"`
	QueueDepth      int           `yaml:"queue_depth"`
	ReconnectMin    time.Duration `yaml:"reconnect_min"`
	ReconnectMax    time.Duration `yaml:"reconnect_max"`
	UpdateManifest  string        `yaml:"update_manifest"`
	UpdateInterval  time.Duration `yaml:"update_interval"`
	UpdateTimeout   time.Duration `yaml:"update_timeout"`
}

func NewCommand(globals *runtimecfg.Options) *cobra.Command {
	opts := &options{
		dialTimeoutMs:   5000,
		dnsCacheTTL:     30 * time.Second,
		dnsNegativeTTL:  5 * time.Second,
		dnsStaleTTL:     2 * time.Minute,
		dnsRefreshAhead: 5 * time.Second,
		readBuffer:      256 * 1024,
		writeBuffer:     256 * 1024,
		maxFrame:        128 * 1024,
		maxInFlight:     16 * 1024 * 1024,
		queueDepth:      512,
		reconnectMin:    2 * time.Second,
		reconnectMax:    30 * time.Second,
		updateInterval:  30 * time.Minute,
		updateTimeout:   30 * time.Second,
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
			if err := opts.loadConfiguration(); err != nil {
				return err
			}
			if err := opts.validate(); err != nil {
				return err
			}
			baseLogger := globals.Logger()
			if baseLogger == nil {
				return errors.New("logger not initialised")
			}
			opts.logger = baseLogger.WithComponent("agent")
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return opts.run(ctx)
		},
	}

	cmd.Flags().StringVar(&opts.configFile, "config", "", "path to agent YAML configuration file")
	cmd.Flags().StringVar(&opts.relayURL, "relay", "", "relay websocket endpoint (wss://host/tunnel)")
	cmd.Flags().StringVar(&opts.agentID, "id", "", "agent identifier")
	cmd.Flags().StringVar(&opts.token, "token", "", "agent shared token")
	cmd.Flags().IntVar(&opts.dialTimeoutMs, "dial-timeout-ms", opts.dialTimeoutMs, "timeout in milliseconds for dialing internal targets")
	cmd.Flags().DurationVar(&opts.dnsCacheTTL, "dns-cache-ttl", opts.dnsCacheTTL, "how long successful DNS answers stay fresh in the agent cache")
	cmd.Flags().DurationVar(&opts.dnsNegativeTTL, "dns-negative-ttl", opts.dnsNegativeTTL, "how long failed or empty DNS answers stay in the negative cache")
	cmd.Flags().DurationVar(&opts.dnsStaleTTL, "dns-stale-ttl", opts.dnsStaleTTL, "how long expired successful DNS answers may be reused while the agent refreshes them")
	cmd.Flags().DurationVar(&opts.dnsRefreshAhead, "dns-refresh-ahead", opts.dnsRefreshAhead, "how soon before expiry the agent refreshes cached DNS answers in the background")
	cmd.Flags().IntVar(&opts.readBuffer, "read-buf", opts.readBuffer, "TCP read buffer size per stream")
	cmd.Flags().IntVar(&opts.writeBuffer, "write-buf", opts.writeBuffer, "websocket write buffer size")
	cmd.Flags().IntVar(&opts.maxFrame, "max-frame", opts.maxFrame, "maximum payload size per frame in bytes")
	cmd.Flags().IntVar(&opts.maxInFlight, "max-inflight", opts.maxInFlight, "maximum unacknowledged bytes per stream (0 disables)")
	cmd.Flags().IntVar(&opts.queueDepth, "stream-queue-depth", opts.queueDepth, "depth of per-stream inbound queue buffers")
	cmd.Flags().StringVar(&opts.updateManifest, "update-manifest", "", "remote JSON manifest describing the latest agent binary")
	cmd.Flags().DurationVar(&opts.updateInterval, "update-interval", opts.updateInterval, "interval between automatic update checks")
	cmd.Flags().DurationVar(&opts.updateTimeout, "update-timeout", opts.updateTimeout, "timeout for update manifest and binary downloads")

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

	switch manifest := strings.TrimSpace(o.updateManifest); strings.ToLower(manifest) {
	case "", "auto":
		o.updateManifest = deriveDefaultUpdateManifestURL(parsed)
	case "off", "disabled", "none", "-":
		o.updateManifest = ""
		o.updateParsedURL = nil
	default:
		updateURL, err := url.Parse(manifest)
		if err != nil {
			return fmt.Errorf("invalid update manifest url: %w", err)
		}
		if updateURL.Scheme != "https" && updateURL.Scheme != "http" {
			return errors.New("update manifest url must use http or https scheme")
		}
		if updateURL.Host == "" {
			return errors.New("update manifest url missing host")
		}
		o.updateManifest = manifest
		o.updateParsedURL = updateURL
	}
	if o.updateManifest != "" && o.updateParsedURL == nil {
		updateURL, err := url.Parse(o.updateManifest)
		if err != nil {
			return fmt.Errorf("invalid update manifest url: %w", err)
		}
		o.updateParsedURL = updateURL
	}

	if o.agentID == "" || o.token == "" {
		return errors.New("--id and --token are required")
	}
	if o.maxFrame <= 0 {
		return errors.New("--max-frame must be positive")
	}
	if o.dnsCacheTTL <= 0 {
		o.dnsCacheTTL = 30 * time.Second
	}
	if o.dnsNegativeTTL <= 0 {
		o.dnsNegativeTTL = 5 * time.Second
	}
	if o.dnsStaleTTL < 0 {
		o.dnsStaleTTL = 0
	}
	o.dnsRefreshAhead = normalizeRefreshAhead(o.dnsCacheTTL, o.dnsRefreshAhead)
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
	if o.updateInterval <= 0 {
		o.updateInterval = 30 * time.Minute
	}
	if o.updateTimeout <= 0 {
		o.updateTimeout = 30 * time.Second
	}
	return nil
}

func (o *options) loadConfiguration() error {
	if o == nil {
		return nil
	}
	configPath := o.configFile
	if configPath == "" {
		configPath = os.Getenv("INTRATUN_AGENT_CONFIG")
	}
	var fileCfg agentFileConfig
	if err := config.LoadYAML(configPath, &fileCfg); err != nil {
		return err
	}
	o.applyFileConfig(fileCfg)
	o.applyEnvOverrides()
	return nil
}

func (o *options) applyFileConfig(cfg agentFileConfig) {
	if cfg.Relay != "" {
		o.relayURL = cfg.Relay
	}
	if cfg.ID != "" {
		o.agentID = cfg.ID
	}
	if cfg.Token != "" {
		o.token = cfg.Token
	}
	if cfg.DialTimeout > 0 {
		o.dialTimeoutMs = cfg.DialTimeout
	}
	if cfg.DNSCacheTTL > 0 {
		o.dnsCacheTTL = cfg.DNSCacheTTL
	}
	if cfg.DNSNegativeTTL > 0 {
		o.dnsNegativeTTL = cfg.DNSNegativeTTL
	}
	if cfg.DNSStaleTTL > 0 {
		o.dnsStaleTTL = cfg.DNSStaleTTL
	}
	if cfg.DNSRefreshAhead > 0 {
		o.dnsRefreshAhead = cfg.DNSRefreshAhead
	}
	if cfg.ReadBuffer > 0 {
		o.readBuffer = cfg.ReadBuffer
	}
	if cfg.WriteBuffer > 0 {
		o.writeBuffer = cfg.WriteBuffer
	}
	if cfg.MaxFrame > 0 {
		o.maxFrame = cfg.MaxFrame
	}
	if cfg.MaxInFlight > 0 {
		o.maxInFlight = cfg.MaxInFlight
	}
	if cfg.QueueDepth > 0 {
		o.queueDepth = cfg.QueueDepth
	}
	if cfg.ReconnectMin > 0 {
		o.reconnectMin = cfg.ReconnectMin
	}
	if cfg.ReconnectMax > 0 {
		o.reconnectMax = cfg.ReconnectMax
	}
	if cfg.UpdateManifest != "" {
		o.updateManifest = cfg.UpdateManifest
	}
	if cfg.UpdateInterval > 0 {
		o.updateInterval = cfg.UpdateInterval
	}
	if cfg.UpdateTimeout > 0 {
		o.updateTimeout = cfg.UpdateTimeout
	}
}

func (o *options) applyEnvOverrides() {
	o.relayURL = config.GetStringEnv("INTRATUN_AGENT_RELAY", o.relayURL)
	o.agentID = config.GetStringEnv("INTRATUN_AGENT_ID", o.agentID)
	o.token = config.GetStringEnv("INTRATUN_AGENT_TOKEN", o.token)
	o.dialTimeoutMs = config.GetIntEnv("INTRATUN_AGENT_DIAL_TIMEOUT_MS", o.dialTimeoutMs)
	o.dnsCacheTTL = config.GetDurationEnv("INTRATUN_AGENT_DNS_CACHE_TTL", o.dnsCacheTTL)
	o.dnsNegativeTTL = config.GetDurationEnv("INTRATUN_AGENT_DNS_NEGATIVE_TTL", o.dnsNegativeTTL)
	o.dnsStaleTTL = config.GetDurationEnv("INTRATUN_AGENT_DNS_STALE_TTL", o.dnsStaleTTL)
	o.dnsRefreshAhead = config.GetDurationEnv("INTRATUN_AGENT_DNS_REFRESH_AHEAD", o.dnsRefreshAhead)
	o.readBuffer = config.GetIntEnv("INTRATUN_AGENT_READ_BUFFER", o.readBuffer)
	o.writeBuffer = config.GetIntEnv("INTRATUN_AGENT_WRITE_BUFFER", o.writeBuffer)
	o.maxFrame = config.GetIntEnv("INTRATUN_AGENT_MAX_FRAME", o.maxFrame)
	o.maxInFlight = config.GetIntEnv("INTRATUN_AGENT_MAX_INFLIGHT", o.maxInFlight)
	o.queueDepth = config.GetIntEnv("INTRATUN_AGENT_QUEUE_DEPTH", o.queueDepth)
	o.reconnectMin = config.GetDurationEnv("INTRATUN_AGENT_RECONNECT_MIN", o.reconnectMin)
	o.reconnectMax = config.GetDurationEnv("INTRATUN_AGENT_RECONNECT_MAX", o.reconnectMax)
	o.updateManifest = config.GetStringEnv("INTRATUN_AGENT_UPDATE_MANIFEST", o.updateManifest)
	o.updateInterval = config.GetDurationEnv("INTRATUN_AGENT_UPDATE_INTERVAL", o.updateInterval)
	o.updateTimeout = config.GetDurationEnv("INTRATUN_AGENT_UPDATE_TIMEOUT", o.updateTimeout)
}

func (o *options) resolverConfig() dialResolverConfig {
	if o == nil {
		return dialResolverConfig{}
	}
	refreshTimeout := 3 * time.Second
	if o.dialTimeoutMs > 0 {
		timeout := time.Duration(o.dialTimeoutMs) * time.Millisecond
		if timeout > 0 {
			refreshTimeout = minDuration(refreshTimeout, timeout)
		}
	}
	return dialResolverConfig{
		PositiveTTL:         o.dnsCacheTTL,
		NegativeTTL:         o.dnsNegativeTTL,
		StaleTTL:            o.dnsStaleTTL,
		RefreshBeforeExpiry: o.dnsRefreshAhead,
		RefreshTimeout:      maxDuration(time.Second, refreshTimeout),
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func normalizeRefreshAhead(ttl time.Duration, requested time.Duration) time.Duration {
	if ttl <= 0 {
		return 5 * time.Second
	}
	if requested <= 0 {
		requested = minDuration(5*time.Second, ttl/2)
	}
	if requested <= 0 {
		requested = ttl
	}
	if requested >= ttl {
		requested = ttl / 2
	}
	if requested <= 0 {
		return ttl
	}
	return requested
}

func deriveDefaultUpdateManifestURL(relayURL *url.URL) string {
	if relayURL == nil {
		return ""
	}
	scheme := "https"
	if relayURL.Scheme == "ws" {
		scheme = "http"
	}
	return (&url.URL{
		Scheme: scheme,
		Host:   relayURL.Host,
		Path:   "/updates/agent/manifest",
	}).String()
}
