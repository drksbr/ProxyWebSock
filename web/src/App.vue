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
import ResourcesSection from "./components/resources/ResourcesSection.vue";
import SummarySection from "./components/summary/SummarySection.vue";
import type {
  MetricsSnapshot,
  NetworkPoint,
  NetworkRates,
  ResourcePoint,
  StatusAgent,
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

const emptyPoint: ResourcePoint = {
  timestamp: "",
  cpuPercent: 0,
  rssBytes: 0,
  goroutines: 0,
};

const emptyStatus: StatusPayload = {
  generatedAt: "",
  proxyAddr: "",
  secureAddr: "",
  socksAddr: "",
  acmeHosts: [],
  agents: [],
  metrics: {
    agentsConnected: 0,
    activeStreams: 0,
    bytesUp: 0,
    bytesDown: 0,
    dialErrors: 0,
    authFailures: 0,
  },
  resources: {
    current: { ...emptyPoint },
    history: [],
  },
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
let pollTimer: number | null = null;

const maxNetworkPoints = computed(
  () =>
    Math.ceil((MAX_HISTORY_MINUTES * 60 * 1000) / refreshIntervalMs.value) + 10,
);

const summaryCards = computed(() => {
  const metrics = data.value.metrics;
  const resources = data.value.resources.current;
  return [
    {
      label: "Agentes Conectados",
      value: formatCount(metrics.agentsConnected),
    },
    { label: "Streams Ativas", value: formatCount(metrics.activeStreams) },
    { label: "CPU", value: formatPercent(resources.cpuPercent) },
    { label: "Memória RSS", value: formatBytes(resources.rssBytes) },
    { label: "Rede In", value: formatRate(netRates.in) },
    { label: "Rede Out", value: formatRate(netRates.out) },
    {
      label: "Bytes (cliente → intranet)",
      value: formatBytes(metrics.bytesUp),
    },
    {
      label: "Bytes (intranet → cliente)",
      value: formatBytes(metrics.bytesDown),
    },
    { label: "Falhas de Dial", value: formatCount(metrics.dialErrors) },
    {
      label: "Falhas de Autenticação",
      value: formatCount(metrics.authFailures),
    },
  ];
});

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

watch(maxNetworkPoints, (limit) => {
  const history = netHistory.value;
  const overflow = history.length - limit;
  if (overflow > 0) {
    history.splice(0, overflow);
  }
});

onMounted(() => {
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
        heartbeatSeq: agent.heartbeatSeq ?? 0,
        heartbeatFailures: agent.heartbeatFailures ?? 0,
        errorCount: agent.errorCount ?? 0,
        lastError: agent.lastError ?? "",
        lastErrorAt: agent.lastErrorAt ?? "",
        acl: agent.acl ?? [],
        streams: agent.streams ?? [],
        autoConfig: agent.autoConfig ?? "",
      };
    },
  );

  return {
    generatedAt: payload.generatedAt ?? "",
    proxyAddr: payload.proxyAddr ?? "",
    secureAddr: payload.secureAddr ?? "",
    socksAddr: payload.socksAddr ?? "",
    acmeHosts: payload.acmeHosts ?? [],
    agents: normalizedAgents,
    metrics: {
      agentsConnected: payload.metrics?.agentsConnected ?? 0,
      activeStreams: payload.metrics?.activeStreams ?? 0,
      bytesUp: payload.metrics?.bytesUp ?? 0,
      bytesDown: payload.metrics?.bytesDown ?? 0,
      dialErrors: payload.metrics?.dialErrors ?? 0,
      authFailures: payload.metrics?.authFailures ?? 0,
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
  };
}

function schedulePoll() {
  pollTimer = window.setTimeout(async () => {
    try {
      const res = await fetch("/status.json", { cache: "no-store" });
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
</script>

<template>
  <div class="min-h-screen bg-slate-950 text-slate-100">
    <div class="mx-auto flex max-w-6xl flex-col gap-10 px-4 py-8">
      <AppHeader
        :proxy-addr="data.proxyAddr"
        :secure-addr="data.secureAddr"
        :socks-addr="data.socksAddr"
        :acme-hosts="data.acmeHosts"
      />

      <SummarySection
        :generated-at="data.generatedAt"
        :refresh-options="REFRESH_OPTIONS"
        :selected-interval="refreshIntervalMs"
        :summary-cards="summaryCards"
        @update:refresh-interval="handleRefreshInterval"
      />

      <ResourcesSection
        :resources="data.resources"
        :range-options="RANGE_OPTIONS"
        :selected-range="rangeMinutes"
        :net-history="netHistory"
        @update:range="handleRangeUpdate"
      />

      <AgentsSection :agents="data.agents" />
    </div>
  </div>
</template>
