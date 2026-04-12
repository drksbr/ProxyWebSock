<script setup lang="ts">
import {
  computed,
  onBeforeUnmount,
  onMounted,
  reactive,
  ref,
  watch,
} from "vue";

import AppHeader from "./components/AppHeader.vue";
import AgentsSection from "./components/agents/AgentsSection.vue";
import ConfigSection from "./components/config/ConfigSection.vue";
import DiagnosticsSection from "./components/diagnostics/DiagnosticsSection.vue";
import EventsSection from "./components/events/EventsSection.vue";
import ResourcesSection from "./components/resources/ResourcesSection.vue";
import SummarySection from "./components/summary/SummarySection.vue";
import { FRONTEND_VERSION } from "./version";
import type {
  MetricsSnapshot,
  NetworkPoint,
  NetworkRates,
  ResourcePoint,
  StatusAgent,
  StatusAgentGroup,
  StatusAuditEvent,
  StatusDiagnosticEvent,
  StatusDestinationProfile,
  StatusRouteEvent,
  StatusSupportSnapshot,
  StatusUpdateCatalogEntry,
  StatusPayload,
} from "./types/status";
import {
  formatBytes,
  formatCount,
  formatPercent,
  formatRate,
} from "./utils/format";

const RANGE_OPTIONS = [
  { label: "10m", minutes: 10 },
  { label: "30m", minutes: 30 },
  { label: "60m", minutes: 60 },
  { label: "1d", minutes: 1440 },
  { label: "5d", minutes: 7200 },
  { label: "7d", minutes: 10080 },
] as const;

const REFRESH_OPTIONS = [
  { label: "0.5s", ms: 500 },
  { label: "1s", ms: 1000 },
  { label: "2s", ms: 2000 },
  { label: "3s", ms: 3000 },
  { label: "5s", ms: 5000 },
  { label: "10s", ms: 10000 },
] as const;

const MAX_HISTORY_MINUTES = Math.max(
  ...RANGE_OPTIONS.map((option) => option.minutes),
);

type TabId = "overview" | "agents" | "config" | "events" | "diagnostics";
const VALID_TABS: TabId[] = ["overview", "agents", "config", "events", "diagnostics"];
const activeTab = ref<TabId>("overview");

function setTab(tab: TabId) {
  activeTab.value = tab;
  window.location.hash = tab;
}

const emptyPoint: ResourcePoint = {
  timestamp: "",
  cpuPercent: 0,
  rssBytes: 0,
  goroutines: 0,
};

const emptySupport: StatusSupportSnapshot = {
  totalFailures: 0,
  routeFailures: 0,
  diagnosticFailures: 0,
  activeBreakers: [],
  quotas: {
    userStreamLimit: 0,
    groupStreamLimit: 0,
    agentStreamLimit: 0,
    users: [],
    groups: [],
    agents: [],
  },
  topDestinations: [],
  topPrincipals: [],
  topAgents: [],
};

const emptyStatus: StatusPayload = {
  generatedAt: "",
  proxyAddr: "",
  secureAddr: "",
  socksAddr: "",
  acmeHosts: [],
  dnsOverrides: [],
  agentGroups: [],
  destinationProfiles: [],
  support: emptySupport,
  auditEvents: [],
  routeEvents: [],
  diagnosticEvents: [],
  downloads: [],
  updateCatalog: [],
  agents: [],
  metrics: {
    agentsConnected: 0,
    activeStreams: 0,
    bytesUp: 0,
    bytesDown: 0,
    dialErrors: 0,
    authFailures: 0,
    routeDecisions: 0,
    routeFailures: 0,
  },
  resources: {
    current: { ...emptyPoint },
    history: [],
  },
  backendVersion: "",
};

declare global {
  interface Window {
    STATUS_BOOTSTRAP?: StatusPayload;
  }
}

const data = ref<StatusPayload>(normalizePayload(window.STATUS_BOOTSTRAP));
const rangeMinutes = ref<number>(60);
const netRates = reactive<NetworkRates>({ in: 0, out: 0 });
const lastMetrics = ref<MetricsSnapshot | null>(null);
const netHistory = ref<NetworkPoint[]>([]);
const refreshIntervalMs = ref<number>(3000);
const frontendVersion = FRONTEND_VERSION;
let pollTimer: number | null = null;

const maxNetworkPoints = computed(
  () =>
    Math.ceil((MAX_HISTORY_MINUTES * 60 * 1000) / refreshIntervalMs.value) + 10,
);

const summaryCards = computed(() => {
  const metrics = data.value.metrics;
  const resources = data.value.resources.current;
  const degradedAgents = data.value.agents.filter(
    (a) => a.status === "degraded",
  ).length;

  const cpuSeverity: "normal" | "warn" | "danger" =
    resources.cpuPercent > 90
      ? "danger"
      : resources.cpuPercent > 75
        ? "warn"
        : "normal";

  const failureRate =
    metrics.routeDecisions > 0
      ? metrics.routeFailures / metrics.routeDecisions
      : 0;
  const routeSeverity: "normal" | "warn" | "danger" =
    failureRate > 0.1 ? "danger" : failureRate > 0.05 ? "warn" : "normal";

  const agentSeverity: "normal" | "warn" =
    degradedAgents > 0 ? "warn" : "normal";

  return [
    {
      label: "Agentes Conectados",
      value: `${formatCount(metrics.agentsConnected)} / ${formatCount(data.value.agents.length)}`,
      severity: agentSeverity,
    },
    {
      label: "Streams Ativas",
      value: formatCount(metrics.activeStreams),
      severity: "normal" as const,
    },
    {
      label: "CPU",
      value: formatPercent(resources.cpuPercent),
      severity: cpuSeverity,
    },
    {
      label: "Memória RSS",
      value: formatBytes(resources.rssBytes),
      severity: "normal" as const,
    },
    {
      label: "Taxa In",
      value: formatRate(netRates.in),
      severity: "normal" as const,
    },
    {
      label: "Taxa Out",
      value: formatRate(netRates.out),
      severity: "normal" as const,
    },
    {
      label: "Decisões de Rota",
      value: formatCount(metrics.routeDecisions),
      severity: "normal" as const,
    },
    {
      label: "Falhas de Rota",
      value: formatCount(metrics.routeFailures),
      severity: routeSeverity,
    },
  ];
});

const dashboardAlerts = computed(() => {
  const alerts: { message: string; severity: "warn" | "danger" }[] = [];
  const degraded = data.value.agents.filter(
    (a) => a.status === "degraded",
  ).length;
  const openBreakers = (data.value.support?.activeBreakers ?? []).filter(
    (b) => b.state === "open",
  ).length;
  if (degraded > 0) {
    alerts.push({
      message: `${degraded} agente${degraded > 1 ? "s" : ""} degradado${degraded > 1 ? "s" : ""}`,
      severity: "warn",
    });
  }
  if (openBreakers > 0) {
    alerts.push({
      message: `${openBreakers} circuit breaker${openBreakers > 1 ? "s" : ""} aberto${openBreakers > 1 ? "s" : ""}`,
      severity: "danger",
    });
  }
  return alerts;
});

const agentsBadge = computed(() => {
  const degraded = data.value.agents.filter(
    (a) => a.status === "degraded",
  ).length;
  return degraded > 0 ? String(degraded) : undefined;
});

const eventsBadge = computed(() => {
  const open = (data.value.support?.activeBreakers ?? []).filter(
    (b) => b.state === "open",
  ).length;
  return open > 0 ? String(open) : undefined;
});

const tabs = computed(() => [
  { id: "overview" as TabId, label: "Visão Geral", badge: undefined as string | undefined, badgeDanger: false },
  { id: "agents" as TabId, label: "Agentes", badge: agentsBadge.value, badgeDanger: false },
  { id: "config" as TabId, label: "Configuração", badge: undefined, badgeDanger: false },
  { id: "events" as TabId, label: "Eventos", badge: eventsBadge.value, badgeDanger: true },
  { id: "diagnostics" as TabId, label: "Diagnóstico", badge: undefined, badgeDanger: false },
]);

watch(refreshIntervalMs, () => {
  restartPolling();
});

watch(
  data,
  (payload) => {
    updateNetworkRates(payload);
  },
  { deep: true, immediate: true },
);

watch(
  () => data.value.backendVersion,
  (backendVersion) => {
    if (backendVersion && backendVersion !== frontendVersion) {
      console.warn(
        "Versão incompatível: backend",
        backendVersion,
        "frontend",
        frontendVersion,
      );
    }
  },
  { immediate: true },
);

watch(maxNetworkPoints, (limit) => {
  const history = netHistory.value;
  const overflow = history.length - limit;
  if (overflow > 0) {
    history.splice(0, overflow);
  }
});

onMounted(() => {
  const hash = window.location.hash.replace("#", "") as TabId;
  if (VALID_TABS.includes(hash)) {
    activeTab.value = hash;
  }
  schedulePoll();
});

onBeforeUnmount(() => {
  if (pollTimer) {
    window.clearTimeout(pollTimer);
    pollTimer = null;
  }
});

function normalizePayload(payload?: StatusPayload): StatusPayload {
  if (!payload) {
    return {
      ...emptyStatus,
      metrics: { ...emptyStatus.metrics },
      resources: {
        current: { ...emptyStatus.resources.current },
        history: [],
      },
      agents: [],
      acmeHosts: [],
      dnsOverrides: [],
      agentGroups: [],
      destinationProfiles: [],
      support: { ...emptySupport },
      auditEvents: [],
      routeEvents: [],
      diagnosticEvents: [],
    };
  }
  const normalizedAgents: StatusAgent[] = (payload.agents ?? []).map(
    (agent) => {
      const rawStatus = agent.status ?? "connected";
      const status: StatusAgent["status"] =
        rawStatus === "degraded"
          ? "degraded"
          : rawStatus === "disconnected"
            ? "disconnected"
            : "connected";
      return {
        id: agent.id ?? "",
        identification: agent.identification ?? agent.id ?? "",
        location: agent.location ?? "",
        status,
        remote: agent.remote ?? "",
        connectedAt: agent.connectedAt ?? "",
        lastHeartbeatAt: agent.lastHeartbeatAt ?? "",
        latencyMillis: agent.latencyMillis ?? 0,
        jitterMillis: agent.jitterMillis ?? 0,
        heartbeatSendDelayMillis: agent.heartbeatSendDelayMillis ?? 0,
        heartbeatSeq: agent.heartbeatSeq ?? 0,
        heartbeatFailures: agent.heartbeatFailures ?? 0,
        heartbeatPending: agent.heartbeatPending ?? 0,
        errorCount: agent.errorCount ?? 0,
        lastError: agent.lastError ?? "",
        lastErrorAt: agent.lastErrorAt ?? "",
        relayControlQueueDepth: agent.relayControlQueueDepth ?? 0,
        relayDataQueueDepth: agent.relayDataQueueDepth ?? 0,
        agentControlQueueDepth: agent.agentControlQueueDepth ?? 0,
        agentDataQueueDepth: agent.agentDataQueueDepth ?? 0,
        agentCpuPercent: agent.agentCpuPercent ?? undefined,
        agentRssBytes: agent.agentRssBytes ?? 0,
        agentGoroutines: agent.agentGoroutines ?? 0,
        goos: agent.goos ?? "",
        goarch: agent.goarch ?? "",
        currentVersion: agent.currentVersion ?? "",
        desiredVersion: agent.desiredVersion ?? "",
        pinnedVersion: agent.pinnedVersion ?? "",
        updateTrack: agent.updateTrack ?? "latest",
        lastUpdateCheckAt: agent.lastUpdateCheckAt ?? "",
        acl: agent.acl ?? [],
        streams: agent.streams ?? [],
        autoConfig: agent.autoConfig ?? "",
      };
    },
  );
  const normalizedGroups: StatusAgentGroup[] = (payload.agentGroups ?? []).map(
    (group) => ({
      id: group.id ?? "",
      name: group.name ?? "",
      slug: group.slug ?? "",
      description: group.description ?? "",
      routingMode: group.routingMode ?? "health-first",
      memberCount: group.memberCount ?? 0,
      enabledMemberCount: group.enabledMemberCount ?? 0,
      legacy: group.legacy ?? false,
      createdAt: group.createdAt ?? "",
      updatedAt: group.updatedAt ?? "",
    }),
  );
  const normalizedProfiles: StatusDestinationProfile[] = (
    payload.destinationProfiles ?? []
  ).map((profile) => ({
    id: profile.id ?? "",
    name: profile.name ?? "",
    slug: profile.slug ?? "",
    host: profile.host ?? "",
    port: profile.port ?? 0,
    protocolHint: profile.protocolHint ?? "",
    defaultGroupId: profile.defaultGroupId ?? "",
    defaultGroupName: profile.defaultGroupName ?? "",
    notes: profile.notes ?? "",
    createdAt: profile.createdAt ?? "",
    updatedAt: profile.updatedAt ?? "",
  }));
  const normalizedSupport: StatusSupportSnapshot = {
    totalFailures: payload.support?.totalFailures ?? 0,
    routeFailures: payload.support?.routeFailures ?? 0,
    diagnosticFailures: payload.support?.diagnosticFailures ?? 0,
    activeBreakers: (payload.support?.activeBreakers ?? []).map((breaker) => ({
      groupId: breaker.groupId ?? "",
      groupName: breaker.groupName ?? "",
      target: breaker.target ?? "",
      state: breaker.state ?? "",
      consecutiveFailures: breaker.consecutiveFailures ?? 0,
      lastError: breaker.lastError ?? "",
      lastFailureAt: breaker.lastFailureAt ?? "",
      openUntil: breaker.openUntil ?? "",
      probeInFlight: breaker.probeInFlight ?? false,
    })),
    quotas: {
      userStreamLimit: payload.support?.quotas?.userStreamLimit ?? 0,
      groupStreamLimit: payload.support?.quotas?.groupStreamLimit ?? 0,
      agentStreamLimit: payload.support?.quotas?.agentStreamLimit ?? 0,
      users: (payload.support?.quotas?.users ?? []).map((counter) => ({
        key: counter.key ?? "",
        label: counter.label ?? "",
        count: counter.count ?? 0,
        limit: counter.limit ?? 0,
        saturated: counter.saturated ?? false,
      })),
      groups: (payload.support?.quotas?.groups ?? []).map((counter) => ({
        key: counter.key ?? "",
        label: counter.label ?? "",
        count: counter.count ?? 0,
        limit: counter.limit ?? 0,
        saturated: counter.saturated ?? false,
      })),
      agents: (payload.support?.quotas?.agents ?? []).map((counter) => ({
        key: counter.key ?? "",
        label: counter.label ?? "",
        count: counter.count ?? 0,
        limit: counter.limit ?? 0,
        saturated: counter.saturated ?? false,
      })),
    },
    topDestinations: (payload.support?.topDestinations ?? []).map((bucket) => ({
      key: bucket.key ?? "",
      label: bucket.label ?? "",
      count: bucket.count ?? 0,
      lastSeen: bucket.lastSeen ?? "",
      sources: bucket.sources ?? [],
    })),
    topPrincipals: (payload.support?.topPrincipals ?? []).map((bucket) => ({
      key: bucket.key ?? "",
      label: bucket.label ?? "",
      count: bucket.count ?? 0,
      lastSeen: bucket.lastSeen ?? "",
      sources: bucket.sources ?? [],
    })),
    topAgents: (payload.support?.topAgents ?? []).map((bucket) => ({
      key: bucket.key ?? "",
      label: bucket.label ?? "",
      count: bucket.count ?? 0,
      lastSeen: bucket.lastSeen ?? "",
      sources: bucket.sources ?? [],
    })),
  };
  const normalizedAuditEvents: StatusAuditEvent[] = (
    payload.auditEvents ?? []
  ).map((event) => ({
    id: event.id ?? "",
    timestamp: event.timestamp ?? "",
    category: event.category ?? "",
    action: event.action ?? "",
    actorType: event.actorType ?? "",
    actorId: event.actorId ?? "",
    actorName: event.actorName ?? "",
    resourceType: event.resourceType ?? "",
    resourceId: event.resourceId ?? "",
    resourceName: event.resourceName ?? "",
    outcome: event.outcome ?? "",
    message: event.message ?? "",
    remoteAddr: event.remoteAddr ?? "",
    metadata: event.metadata ?? {},
  }));
  const normalizedRouteEvents: StatusRouteEvent[] = (
    payload.routeEvents ?? []
  ).map((event) => ({
    timestamp: event.timestamp ?? "",
    protocol: event.protocol ?? "",
    outcome: event.outcome ?? "",
    reasonCode: event.reasonCode ?? "",
    message: event.message ?? "",
    target: event.target ?? "",
    principalType: event.principalType ?? "",
    principalName: event.principalName ?? "",
    groupId: event.groupId ?? "",
    groupName: event.groupName ?? "",
    profileId: event.profileId ?? "",
    profileName: event.profileName ?? "",
    agentId: event.agentId ?? "",
    agentName: event.agentName ?? "",
    candidateCount: event.candidateCount ?? 0,
    selectedStatus: event.selectedStatus ?? "",
  }));
  const normalizedDiagnosticEvents: StatusDiagnosticEvent[] = (
    payload.diagnosticEvents ?? []
  ).map((event) => ({
    timestamp: event.timestamp ?? "",
    mode: event.mode ?? "",
    outcome: event.outcome ?? "",
    host: event.host ?? "",
    port: event.port ?? 0,
    target: event.target ?? "",
    agentId: event.agentId ?? "",
    agentName: event.agentName ?? "",
    groupId: event.groupId ?? "",
    groupName: event.groupName ?? "",
    profileId: event.profileId ?? "",
    profileName: event.profileName ?? "",
    overrideAddress: event.overrideAddress ?? "",
    reasonCode: event.reasonCode ?? "",
    message: event.message ?? "",
    selectedStatus: event.selectedStatus ?? "",
    candidateCount: event.candidateCount ?? 0,
    startedAt: event.startedAt ?? "",
    finishedAt: event.finishedAt ?? "",
    durationMillis: event.durationMillis ?? 0,
    steps: (event.steps ?? []).map((step) => ({
      step: step.step ?? "",
      success: step.success ?? false,
      durationMillis: step.durationMillis ?? 0,
      message: step.message ?? "",
      resolutionSource: step.resolutionSource ?? "",
      addresses: step.addresses ?? [],
      selectedAddress: step.selectedAddress ?? "",
      tlsServerName: step.tlsServerName ?? "",
      tlsVersion: step.tlsVersion ?? "",
      tlsCipherSuite: step.tlsCipherSuite ?? "",
      tlsPeerNames: step.tlsPeerNames ?? [],
    })),
  }));

  return {
    generatedAt: payload.generatedAt ?? "",
    proxyAddr: payload.proxyAddr ?? "",
    secureAddr: payload.secureAddr ?? "",
    socksAddr: payload.socksAddr ?? "",
    acmeHosts: payload.acmeHosts ?? [],
    dnsOverrides: payload.dnsOverrides ?? [],
    agentGroups: normalizedGroups,
    destinationProfiles: normalizedProfiles,
    support: normalizedSupport,
    auditEvents: normalizedAuditEvents,
    routeEvents: normalizedRouteEvents,
    diagnosticEvents: normalizedDiagnosticEvents,
    downloads: payload.downloads ?? [],
    updateCatalog: (payload.updateCatalog ?? []) as StatusUpdateCatalogEntry[],
    agents: normalizedAgents,
    metrics: {
      agentsConnected: payload.metrics?.agentsConnected ?? 0,
      activeStreams: payload.metrics?.activeStreams ?? 0,
      bytesUp: payload.metrics?.bytesUp ?? 0,
      bytesDown: payload.metrics?.bytesDown ?? 0,
      dialErrors: payload.metrics?.dialErrors ?? 0,
      authFailures: payload.metrics?.authFailures ?? 0,
      routeDecisions: payload.metrics?.routeDecisions ?? 0,
      routeFailures: payload.metrics?.routeFailures ?? 0,
    },
    resources: {
      current: {
        timestamp: payload.resources?.current?.timestamp ?? "",
        cpuPercent: payload.resources?.current?.cpuPercent ?? 0,
        rssBytes: payload.resources?.current?.rssBytes ?? 0,
        goroutines: payload.resources?.current?.goroutines ?? 0,
      },
      history: payload.resources?.history ?? [],
    },
    backendVersion: payload.backendVersion ?? "",
  };
}

function schedulePoll() {
  pollTimer = window.setTimeout(async () => {
    try {
      const res = await fetch("/status.json", {
        cache: "no-store",
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const payload = (await res.json()) as StatusPayload;
      data.value = normalizePayload(payload);
    } catch (err) {
      console.warn("status refresh failed", err);
    } finally {
      schedulePoll();
    }
  }, refreshIntervalMs.value);
}

function restartPolling() {
  if (pollTimer) {
    window.clearTimeout(pollTimer);
    pollTimer = null;
  }
  schedulePoll();
}

function updateNetworkRates(payload: StatusPayload) {
  const metrics = payload.metrics;
  const generatedAt = new Date(payload.generatedAt);
  if (Number.isNaN(generatedAt.getTime())) {
    lastMetrics.value = null;
    netRates.in = 0;
    netRates.out = 0;
    return;
  }

  const now = generatedAt.getTime();
  const previous = lastMetrics.value;
  if (previous) {
    const dt = (now - previous.timestamp) / 1000;
    if (dt > 0) {
      const inbound = metrics.bytesUp - previous.bytesUp;
      const outbound = metrics.bytesDown - previous.bytesDown;
      netRates.in = Math.max(inbound / dt, 0);
      netRates.out = Math.max(outbound / dt, 0);
    } else {
      netRates.in = 0;
      netRates.out = 0;
    }
  } else {
    netRates.in = 0;
    netRates.out = 0;
  }

  lastMetrics.value = {
    bytesUp: metrics.bytesUp,
    bytesDown: metrics.bytesDown,
    timestamp: now,
  };

  appendNetworkHistory(now, netRates);
}

function appendNetworkHistory(timestamp: number, rates: NetworkRates) {
  netHistory.value.push({
    timestamp,
    inbound: rates.in,
    outbound: rates.out,
  });
  const overflow = netHistory.value.length - maxNetworkPoints.value;
  if (overflow > 0) {
    netHistory.value.splice(0, overflow);
  }
}

function handleRefreshInterval(ms: number) {
  refreshIntervalMs.value = ms;
}

function handleRangeUpdate(minutes: number) {
  rangeMinutes.value = minutes;
}

async function reloadStatusNow() {
  try {
    const res = await fetch("/status.json", {
      cache: "no-store",
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    const payload = (await res.json()) as StatusPayload;
    data.value = normalizePayload(payload);
  } catch (err) {
    console.warn("status reload failed", err);
  }
}
</script>

<template>
  <div class="min-h-screen bg-slate-950 text-slate-100">
    <!-- Header compacto fixo -->
    <AppHeader
      :proxy-addr="data.proxyAddr"
      :secure-addr="data.secureAddr"
      :socks-addr="data.socksAddr"
      :acme-hosts="data.acmeHosts"
      :downloads="data.downloads ?? []"
      :backend-version="data.backendVersion ?? ''"
      :frontend-version="frontendVersion"
      :refresh-options="REFRESH_OPTIONS"
      :selected-interval="refreshIntervalMs"
      @update:refresh-interval="handleRefreshInterval"
    />

    <!-- Barra de abas (sticky, abaixo do header) -->
    <div class="sticky top-[53px] z-30 border-b border-slate-800 bg-slate-950/95 backdrop-blur">
      <div class="mx-auto max-w-7xl px-4">
        <nav class="flex overflow-x-auto">
          <button
            v-for="tab in tabs"
            :key="tab.id"
            type="button"
            class="flex shrink-0 items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium transition"
            :class="
              activeTab === tab.id
                ? 'border-sky-400 text-sky-100'
                : 'border-transparent text-slate-400 hover:border-slate-600 hover:text-slate-200'
            "
            @click="setTab(tab.id)"
          >
            {{ tab.label }}
            <span
              v-if="tab.badge"
              class="rounded-full px-1.5 py-0.5 text-[10px] font-bold leading-none"
              :class="tab.badgeDanger ? 'bg-rose-500/30 text-rose-200' : 'bg-amber-500/30 text-amber-200'"
            >{{ tab.badge }}</span>
          </button>
        </nav>
      </div>
    </div>

    <!-- Conteúdo por aba -->
    <div class="mx-auto max-w-7xl space-y-6 px-4 py-6">
      <!-- Visão Geral -->
      <template v-if="activeTab === 'overview'">
        <SummarySection
          :generated-at="data.generatedAt"
          :summary-cards="summaryCards"
          :alerts="dashboardAlerts"
        />
        <ResourcesSection
          :resources="data.resources"
          :range-options="RANGE_OPTIONS"
          :selected-range="rangeMinutes"
          :net-history="netHistory"
          @update:range="handleRangeUpdate"
        />
      </template>

      <!-- Agentes -->
      <template v-if="activeTab === 'agents'">
        <AgentsSection
          :agents="data.agents"
          :update-catalog="data.updateCatalog ?? []"
          @refresh-requested="reloadStatusNow"
        />
      </template>

      <!-- Configuração -->
      <template v-if="activeTab === 'config'">
        <ConfigSection
          :agent-groups="data.agentGroups ?? []"
          :destination-profiles="data.destinationProfiles ?? []"
          :agents="data.agents"
          :dns-overrides="data.dnsOverrides ?? []"
          @refresh-requested="reloadStatusNow"
        />
      </template>

      <!-- Eventos -->
      <template v-if="activeTab === 'events'">
        <EventsSection
          :support="data.support ?? emptySupport"
          :route-events="data.routeEvents ?? []"
          :audit-events="data.auditEvents ?? []"
        />
      </template>

      <!-- Diagnóstico -->
      <template v-if="activeTab === 'diagnostics'">
        <DiagnosticsSection
          :agents="data.agents"
          :agent-groups="data.agentGroups ?? []"
          :destination-profiles="data.destinationProfiles ?? []"
          :diagnostic-events="data.diagnosticEvents ?? []"
        />
      </template>
    </div>
  </div>
</template>
