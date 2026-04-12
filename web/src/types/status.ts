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
  resolvedTarget?: string;
  resolutionSource?: string;
  principalType?: string;
  principalName?: string;
  groupId?: string;
  groupName?: string;
  profileId?: string;
  profileName?: string;
  routeReasonCode?: string;
  routeReason?: string;
  protocol: string;
  createdAt: string;
  bytesUp: number;
  bytesDown: number;
  pendingClientBytes?: number;
  pendingClientChunks?: number;
  clientBacklogLimit?: number;
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
  heartbeatSendDelayMillis?: number;
  heartbeatSeq?: number;
  heartbeatFailures?: number;
  heartbeatPending?: number;
  errorCount?: number;
  lastError?: string;
  lastErrorAt?: string;
  relayControlQueueDepth?: number;
  relayDataQueueDepth?: number;
  agentControlQueueDepth?: number;
  agentDataQueueDepth?: number;
  agentCpuPercent?: number;
  agentRssBytes?: number;
  agentGoroutines?: number;
  goos?: string;
  goarch?: string;
  currentVersion?: string;
  desiredVersion?: string;
  pinnedVersion?: string;
  updateTrack?: "latest" | "pinned" | string;
  lastUpdateCheckAt?: string;
  acl?: string[];
  streams?: StatusStream[];
  autoConfig?: string;
};

export type StatusMetrics = {
  agentsConnected: number;
  activeStreams: number;
  bytesUp: number;
  bytesDown: number;
  dialErrors: number;
  authFailures: number;
  routeDecisions: number;
  routeFailures: number;
};

export type StatusDownload = {
  label: string;
  goos: string;
  goarch: string;
  url: string;
  fileName: string;
  version?: string;
};

export type StatusDNSOverride = {
  host: string;
  address: string;
  updatedAt?: string;
};

export type StatusAgentGroup = {
  id: string;
  name: string;
  slug: string;
  description?: string;
  routingMode?: string;
  memberCount?: number;
  enabledMemberCount?: number;
  legacy?: boolean;
  createdAt?: string;
  updatedAt?: string;
};

export type StatusDestinationProfile = {
  id: string;
  name: string;
  slug: string;
  host: string;
  port: number;
  protocolHint?: string;
  defaultGroupId?: string;
  defaultGroupName?: string;
  notes?: string;
  createdAt?: string;
  updatedAt?: string;
};

export type StatusUpdateCatalogEntry = {
  goos: string;
  goarch: string;
  latestVersion?: string;
  versions: string[];
};

export type StatusRouteEvent = {
  timestamp: string;
  protocol: string;
  outcome: string;
  reasonCode?: string;
  message?: string;
  target: string;
  principalType?: string;
  principalName?: string;
  groupId?: string;
  groupName?: string;
  profileId?: string;
  profileName?: string;
  agentId?: string;
  agentName?: string;
  candidateCount?: number;
  selectedStatus?: string;
};

export type StatusAuditEvent = {
  id: string;
  timestamp: string;
  category: string;
  action: string;
  actorType?: string;
  actorId?: string;
  actorName?: string;
  resourceType?: string;
  resourceId?: string;
  resourceName?: string;
  outcome?: string;
  message?: string;
  remoteAddr?: string;
  metadata?: Record<string, string>;
};

export type StatusSupportBucket = {
  key: string;
  label: string;
  count: number;
  lastSeen?: string;
  sources?: string[];
};

export type StatusCircuitBreaker = {
  groupId?: string;
  groupName?: string;
  target: string;
  state: string;
  consecutiveFailures?: number;
  lastError?: string;
  lastFailureAt?: string;
  openUntil?: string;
  probeInFlight?: boolean;
};

export type StatusQuotaCounter = {
  key: string;
  label: string;
  count: number;
  limit?: number;
  saturated?: boolean;
};

export type StatusQuotaSnapshot = {
  userStreamLimit: number;
  groupStreamLimit: number;
  agentStreamLimit: number;
  users?: StatusQuotaCounter[];
  groups?: StatusQuotaCounter[];
  agents?: StatusQuotaCounter[];
};

export type StatusSupportSnapshot = {
  totalFailures: number;
  routeFailures: number;
  diagnosticFailures: number;
  activeBreakers?: StatusCircuitBreaker[];
  quotas?: StatusQuotaSnapshot;
  topDestinations?: StatusSupportBucket[];
  topPrincipals?: StatusSupportBucket[];
  topAgents?: StatusSupportBucket[];
};

export type StatusDiagnosticStep = {
  step: string;
  success: boolean;
  durationMillis?: number;
  message?: string;
  resolutionSource?: string;
  addresses?: string[];
  selectedAddress?: string;
  tlsServerName?: string;
  tlsVersion?: string;
  tlsCipherSuite?: string;
  tlsPeerNames?: string[];
};

export type StatusDiagnosticEvent = {
  timestamp: string;
  mode?: string;
  outcome: string;
  host: string;
  port: number;
  target: string;
  agentId?: string;
  agentName?: string;
  groupId?: string;
  groupName?: string;
  profileId?: string;
  profileName?: string;
  overrideAddress?: string;
  reasonCode?: string;
  message?: string;
  selectedStatus?: string;
  candidateCount?: number;
  startedAt?: string;
  finishedAt?: string;
  durationMillis?: number;
  steps?: StatusDiagnosticStep[];
};

export type StatusPayload = {
  generatedAt: string;
  proxyAddr: string;
  secureAddr: string;
  socksAddr: string;
  acmeHosts: string[];
  dnsOverrides?: StatusDNSOverride[];
  agentGroups?: StatusAgentGroup[];
  destinationProfiles?: StatusDestinationProfile[];
  support?: StatusSupportSnapshot;
  auditEvents?: StatusAuditEvent[];
  routeEvents?: StatusRouteEvent[];
  diagnosticEvents?: StatusDiagnosticEvent[];
  downloads?: StatusDownload[];
  updateCatalog?: StatusUpdateCatalogEntry[];
  agents: StatusAgent[];
  metrics: StatusMetrics;
  resources: ResourceSnapshot;
  backendVersion?: string;
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
