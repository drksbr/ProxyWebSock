export type ResourcePoint = {
  timestamp: string;
  cpuPercent: number;
  rssBytes: number;
  goroutines: number;
};

export type ResourceSnapshot = {
  current: ResourcePoint;
  history: ResourcePoint[];
};

export type StatusStream = {
  streamId: string;
  target: string;
  protocol: string;
  createdAt: string;
  bytesUp: number;
  bytesDown: number;
};

export type StatusAgent = {
  id: string;
  identification?: string;
  location?: string;
  status: "connected" | "degraded" | "disconnected";
  remote?: string;
  connectedAt?: string;
  lastHeartbeatAt?: string;
  latencyMillis?: number;
  jitterMillis?: number;
  heartbeatSeq?: number;
  heartbeatFailures?: number;
  errorCount?: number;
  lastError?: string;
  lastErrorAt?: string;
  acl?: string[];
  streams: StatusStream[];
  autoConfig?: string;
};

export type StatusMetrics = {
  agentsConnected: number;
  activeStreams: number;
  bytesUp: number;
  bytesDown: number;
  dialErrors: number;
  authFailures: number;
};

export type StatusPayload = {
  generatedAt: string;
  proxyAddr: string;
  secureAddr: string;
  socksAddr: string;
  acmeHosts: string[];
  agents: StatusAgent[];
  metrics: StatusMetrics;
  resources: ResourceSnapshot;
};

export type NetworkRates = {
  in: number;
  out: number;
};

export type MetricsSnapshot = {
  bytesUp: number;
  bytesDown: number;
  timestamp: number;
};

export type NetworkPoint = {
  timestamp: number;
  inbound: number;
  outbound: number;
};
