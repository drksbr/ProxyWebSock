export type DiagnosticRunRequest = {
  agentId?: string;
  groupId?: string;
  profileId?: string;
  host?: string;
  port?: number;
  tlsEnabled: boolean;
  tlsServerName?: string;
  tlsSkipVerify?: boolean;
  timeoutMs?: number;
};

export type DiagnosticStepResult = {
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

export type DiagnosticRunResponse = {
  mode?: string;
  agentId?: string;
  agentName?: string;
  groupId?: string;
  groupName?: string;
  profileId?: string;
  profileName?: string;
  host: string;
  port: number;
  overrideAddress?: string;
  reasonCode?: string;
  reason?: string;
  selectedStatus?: string;
  candidateCount?: number;
  startedAt?: string;
  finishedAt?: string;
  durationMillis?: number;
  success: boolean;
  error?: string;
  steps: DiagnosticStepResult[];
};
