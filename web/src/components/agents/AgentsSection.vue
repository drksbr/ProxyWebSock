<script setup lang="ts">
import { computed, reactive, ref, watch } from "vue";

import type {
  StatusAgent,
  StatusStream,
  StatusUpdateCatalogEntry,
} from "../../types/status";
import {
  formatAbsolute,
  formatBytes,
  formatCount,
  formatMillis,
  formatRelative,
  formatPercent,
} from "../../utils/format";

const props = defineProps<{
  agents: StatusAgent[];
  updateCatalog: StatusUpdateCatalogEntry[];
}>();

const emit = defineEmits<{
  (e: "refreshRequested"): void;
}>();

const agentSearch = ref("");
const connectionSearch = ref("");
const expandedAgents = ref<Set<string>>(new Set());
const deploymentSelections = reactive<Record<string, string>>({});
const deploymentBusy = reactive<Record<string, boolean>>({});
const deploymentMessage = reactive<Record<string, string>>({});
const deploymentError = reactive<Record<string, string>>({});

const filteredAgents = computed(() => {
  const query = agentSearch.value.trim().toLowerCase();
  const destinationQuery = connectionSearch.value.trim().toLowerCase();
  return props.agents.filter((agent) => {
    const haystack =
      `${agent.id} ${agent.remote ?? ""} ${agent.identification ?? ""} ${agent.location ?? ""}`.toLowerCase();
    if (query && !haystack.includes(query)) {
      return false;
    }
    if (!destinationQuery) return true;
    const streams = agent.streams ?? [];
    return streams.some((stream) => {
      const target = stream.target?.toLowerCase() ?? "";
      return target.includes(destinationQuery);
    });
  });
});

const hasAgents = computed(() => filteredAgents.value.length > 0);

const connectedAgentsCount = computed(
  () => props.agents.filter((agent) => agent.status !== "disconnected").length,
);

const degradedAgentsCount = computed(
  () => props.agents.filter((agent) => agent.status === "degraded").length,
);

watch(
  () => props.agents,
  (agents) => {
    const ids = agents.map((agent) => agent.id);
    const available = new Set(ids);
    const next = new Set<string>();
    expandedAgents.value.forEach((id) => {
      if (available.has(id)) {
        next.add(id);
      }
    });
    expandedAgents.value = next;

    agents.forEach((agent) => {
      if (!deploymentSelections[agent.id]) {
        deploymentSelections[agent.id] = agent.pinnedVersion || "latest";
      }
    });
  },
  { immediate: true },
);

function toggleAgent(agentId: string) {
  const next = new Set(expandedAgents.value);
  if (next.has(agentId)) {
    next.delete(agentId);
  } else {
    next.add(agentId);
  }
  expandedAgents.value = next;
}

function isExpanded(agentId: string) {
  return expandedAgents.value.has(agentId);
}

function clearConnectionFilters() {
  connectionSearch.value = "";
}

function streamsForDisplay(agent: StatusAgent): StatusStream[] {
  const query = connectionSearch.value.trim().toLowerCase();
  if (!query) {
    return agent.streams ?? [];
  }
  return (agent.streams ?? []).filter((stream) =>
    (stream.target?.toLowerCase() ?? "").includes(query),
  );
}

function statusLabel(status: StatusAgent["status"]): string {
  switch (status) {
    case "degraded":
      return "Degradado";
    case "disconnected":
      return "Desconectado";
    default:
      return "Conectado";
  }
}

function statusBadgeClass(status: StatusAgent["status"]): string {
  const base =
    "rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide";
  switch (status) {
    case "degraded":
      return `${base} bg-amber-500/20 text-amber-200 border border-amber-400/40`;
    case "disconnected":
      return `${base} bg-slate-800/60 text-slate-400 border border-slate-700`;
    default:
      return `${base} bg-emerald-500/20 text-emerald-200 border border-emerald-400/40`;
  }
}

function agentCardClasses(agent: StatusAgent): string {
  const base =
    "overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60 shadow-lg shadow-slate-950/40 transition";
  if (agent.status === "disconnected") {
    return `${base} border-dashed border-slate-800/70 opacity-70`;
  }
  if (agent.status === "degraded") {
    return `${base} border-amber-500/40`;
  }
  return base;
}

function updateCatalogEntry(agent: StatusAgent) {
  return props.updateCatalog.find(
    (entry) => entry.goos === agent.goos && entry.goarch === agent.goarch,
  );
}

function versionsForAgent(agent: StatusAgent): string[] {
  return updateCatalogEntry(agent)?.versions ?? [];
}

function latestVersionForAgent(agent: StatusAgent): string {
  return updateCatalogEntry(agent)?.latestVersion ?? "";
}

function selectedDeployment(agent: StatusAgent): string {
  return deploymentSelections[agent.id] || agent.pinnedVersion || "latest";
}

function currentVersionLabel(agent: StatusAgent): string {
  return agent.currentVersion || "-";
}

function desiredVersionLabel(agent: StatusAgent): string {
  if (agent.desiredVersion) {
    return agent.desiredVersion;
  }
  return latestVersionForAgent(agent) || "-";
}

function trackLabel(agent: StatusAgent): string {
  return agent.updateTrack === "pinned" ? "fixado" : "latest";
}

function canManageDeployment(agent: StatusAgent): boolean {
  return Boolean(agent.goos && agent.goarch && versionsForAgent(agent).length);
}

function resolutionSourceLabel(source?: string): string {
  switch (source) {
    case "override":
      return "override";
    case "dns-cache":
      return "dns cache";
    case "dns":
      return "dns local";
    case "literal":
      return "ip literal";
    default:
      return source || "-";
  }
}

async function applyDeployment(agent: StatusAgent) {
  deploymentBusy[agent.id] = true;
  deploymentError[agent.id] = "";
  deploymentMessage[agent.id] = "";

  try {
    const version = selectedDeployment(agent);
    const res = await fetch(`/api/agents/${encodeURIComponent(agent.id)}/deployment`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        version: version === "latest" ? "" : version,
        goos: agent.goos,
        goarch: agent.goarch,
        forceCheck: true,
      }),
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    const payload = (await res.json()) as {
      desiredVersion?: string;
      forceDispatched?: boolean;
    };
    deploymentSelections[agent.id] = version;
    deploymentMessage[agent.id] = payload.forceDispatched
      ? "Deployment salvo e check imediato enviado."
      : "Deployment salvo. O agente vai aplicar no próximo poll HTTP.";
    emit("refreshRequested");
  } catch (err) {
    deploymentError[agent.id] =
      err instanceof Error ? err.message : "Falha ao aplicar deployment.";
  } finally {
    deploymentBusy[agent.id] = false;
  }
}
</script>

<template>
  <section>
    <div class="mb-4 flex items-center justify-between">
      <h2 class="text-xl font-semibold">Agentes</h2>
      <div class="text-sm text-slate-400">
        {{ connectedAgentsCount }} ativos ·
        {{ agents.length }} cadastrados
        <span v-if="degradedAgentsCount">· {{ degradedAgentsCount }} degradados</span>
      </div>
    </div>
    <div class="grid gap-4 rounded-xl border border-slate-800 bg-slate-900/40 p-4 mb-4">
      <div class="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
          Buscar agente
          <input v-model="agentSearch" type="search" placeholder="ID ou endereço remoto"
            class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400" />
        </label>
        <div class="flex flex-col gap-2">
          <div class="flex items-center justify-between text-sm font-medium text-slate-300">
            <span>Filtrar por destino</span>
            <button v-if="connectionSearch" type="button"
              class="text-xs font-semibold uppercase tracking-wide text-slate-400 hover:text-slate-200"
              @click="clearConnectionFilters">
              Limpar
            </button>
          </div>
          <input v-model="connectionSearch" type="search" placeholder="Destino, ex: intranet.local:443"
            class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400" />
          <p class="text-xs text-slate-500">
            Usa o campo destino das streams ativas.
          </p>
        </div>
      </div>
    </div>
    <div v-if="hasAgents" class="space-y-4">
      <article v-for="agent in filteredAgents" :key="agent.id" :class="agentCardClasses(agent)">
        <button type="button"
          class="flex w-full items-start justify-between gap-4 border-b border-slate-800 bg-slate-900/70 px-5 py-4 text-left transition hover:bg-slate-900/90"
          @click="toggleAgent(agent.id)">
          <div class="space-y-2">
            <div class="flex flex-wrap items-center gap-2">
              <div class="text-lg font-semibold text-slate-100">
                {{ agent.identification || agent.id }}
              </div>
              <span :class="statusBadgeClass(agent.status)">
                {{ statusLabel(agent.status) }}
              </span>
            </div>
            <div class="text-xs text-slate-400">
              <span class="font-mono text-slate-300">{{ agent.id }}</span>
              <span v-if="agent.location"> · {{ agent.location }}</span>
            </div>
            <div v-if="agent.remote" class="text-xs text-slate-500">
              Remoto {{ agent.remote }}
            </div>
            <div class="text-xs text-slate-500">
              <template v-if="agent.status !== 'disconnected' && agent.connectedAt">
                Conectado há {{ formatRelative(agent.connectedAt) }}
              </template>
              <template v-else-if="agent.lastHeartbeatAt">
                Último heartbeat {{ formatRelative(agent.lastHeartbeatAt) }}
              </template>
              <template v-else> Último heartbeat: - </template>
            </div>
            <div v-if="agent.currentVersion || agent.goos" class="text-xs text-slate-500">
              <span v-if="agent.currentVersion">Versão {{ agent.currentVersion }}</span>
              <span v-if="agent.goos && agent.goarch">
                {{ agent.currentVersion ? " · " : "" }}{{ agent.goos }}/{{ agent.goarch }}
              </span>
            </div>
          </div>
          <div class="flex flex-wrap items-center gap-3">
            <span
              class="rounded-full bg-slate-800/80 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-slate-300">
              {{ agent.streams?.length ?? 0 }}
              {{
                (agent.streams?.length ?? 0) === 1 ? "stream" : "streams"
              }}
            </span>
            <span v-if="(agent.latencyMillis ?? 0) > 0"
              class="rounded-full bg-slate-800/80 px-3 py-1 text-xs font-semibold text-slate-300">
              RTT {{ formatMillis(agent.latencyMillis) }}
            </span>
            <span v-if="agent.heartbeatFailures"
              class="rounded-full bg-amber-500/20 px-3 py-1 text-xs font-semibold text-amber-200">
              {{ agent.heartbeatFailures }} HB falhos
            </span>
            <span class="text-slate-500 transition-transform" :class="isExpanded(agent.id) ? 'rotate-90' : ''">
              ▶
            </span>
          </div>
        </button>
        <div v-if="isExpanded(agent.id)" class="space-y-2 px-5 py-4">
          <div class="grid gap-2 text-sm text-slate-300 md:grid-cols-2 lg:grid-cols-3">
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                ID
              </div>
              <div class="font-mono text-sm text-slate-100 break-all">
                {{ agent.id }}
              </div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Identificação
              </div>
              <div>{{ agent.identification || "-" }}</div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Localização
              </div>
              <div>{{ agent.location || "-" }}</div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Status
              </div>
              <div>{{ statusLabel(agent.status) }}</div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Remoto
              </div>
              <div class="font-mono text-sm text-slate-100 break-all">
                {{ agent.remote || "-" }}
              </div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Conectado
              </div>
              <div>
                {{
                  agent.connectedAt ? formatAbsolute(agent.connectedAt) : "-"
                }}
              </div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Plataforma
              </div>
              <div class="font-mono text-sm text-slate-100">
                {{ agent.goos && agent.goarch ? `${agent.goos}/${agent.goarch}` : "-" }}
              </div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Versão atual
              </div>
              <div class="font-mono text-sm text-slate-100">
                {{ currentVersionLabel(agent) }}
              </div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Deployment alvo
              </div>
              <div class="font-mono text-sm text-slate-100">
                {{ desiredVersionLabel(agent) }}
              </div>
              <div class="mt-1 text-xs text-slate-500">
                Modo {{ trackLabel(agent) }}
              </div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Auto Config
              </div>
              <template v-if="agent.autoConfig">
                <a :href="agent.autoConfig" class="text-teal-400 transition hover:text-teal-200">
                  Download PAC
                </a>
              </template>
              <span v-else class="text-slate-500">Indisponível</span>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3 lg:col-span-2">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Último erro
              </div>
              <div v-if="agent.lastError" class="space-y-1">
                <div class="text-slate-200">{{ agent.lastError }}</div>
                <div class="text-xs text-slate-500">
                  {{ formatRelative(agent.lastErrorAt ?? "") }} ({{
                    formatAbsolute(agent.lastErrorAt ?? "")
                  }})
                </div>
              </div>
              <div v-else class="text-slate-500">Nenhum</div>
            </div>
          </div>

          <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
            <div class="mb-3 flex items-center justify-between gap-3">
              <div>
                <div class="text-xs uppercase tracking-wide text-slate-500">
                  Deployment do agente
                </div>
                <div class="text-sm text-slate-300">
                  Força upgrade ou downgrade por HTTP, sem depender do túnel WebSocket.
                </div>
              </div>
              <div v-if="agent.lastUpdateCheckAt" class="text-xs text-slate-500">
                Último poll {{ formatRelative(agent.lastUpdateCheckAt) }}
              </div>
            </div>
            <div v-if="canManageDeployment(agent)" class="grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto]">
              <label class="flex flex-col gap-2 text-sm text-slate-300">
                Versão alvo
                <select
                  v-model="deploymentSelections[agent.id]"
                  class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
                >
                  <option value="latest">
                    Seguir latest{{ latestVersionForAgent(agent) ? ` (${latestVersionForAgent(agent)})` : "" }}
                  </option>
                  <option v-for="releaseVersion in versionsForAgent(agent)" :key="releaseVersion" :value="releaseVersion">
                    {{ releaseVersion }}
                  </option>
                </select>
              </label>
              <button
                type="button"
                class="rounded-lg border border-sky-500/50 bg-sky-500/15 px-4 py-2 text-sm font-semibold text-sky-100 transition hover:bg-sky-500/25 disabled:cursor-not-allowed disabled:opacity-60"
                :disabled="deploymentBusy[agent.id]"
                @click="applyDeployment(agent)"
              >
                {{ deploymentBusy[agent.id] ? "Aplicando..." : "Aplicar e forçar check" }}
              </button>
            </div>
            <div v-else class="rounded-lg border border-dashed border-slate-800 bg-slate-900/80 p-3 text-sm text-slate-400">
              Plataforma ainda não identificada ou sem artefatos publicados para esse agente.
            </div>
            <div v-if="deploymentMessage[agent.id]" class="mt-3 text-sm text-emerald-300">
              {{ deploymentMessage[agent.id] }}
            </div>
            <div v-if="deploymentError[agent.id]" class="mt-3 text-sm text-rose-300">
              {{ deploymentError[agent.id] }}
            </div>
          </div>

          <div class="grid gap-2 text-sm text-slate-300 md:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6">
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Último heartbeat
              </div>
              <div>
                {{
                  agent.lastHeartbeatAt
                    ? formatAbsolute(agent.lastHeartbeatAt)
                    : "-"
                }}
              </div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Latência (RTT)
              </div>
              <div>{{ formatMillis(agent.latencyMillis) }}</div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Jitter
              </div>
              <div>{{ formatMillis(agent.jitterMillis) }}</div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Atraso envio HB
              </div>
              <div>{{ formatMillis(agent.heartbeatSendDelayMillis) }}</div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                HB pendentes
              </div>
              <div>{{ formatCount(agent.heartbeatPending ?? 0) }}</div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Erros acumulados
              </div>
              <div>{{ formatCount(agent.errorCount ?? 0) }}</div>
            </div>
          </div>

          <div class="grid gap-2 text-sm text-slate-300 md:grid-cols-2 lg:grid-cols-4">
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Fila controle (relay)
              </div>
              <div>{{ formatCount(agent.relayControlQueueDepth ?? 0) }}</div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Fila dados (relay)
              </div>
              <div>{{ formatCount(agent.relayDataQueueDepth ?? 0) }}</div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Fila controle (agente)
              </div>
              <div>{{ formatCount(agent.agentControlQueueDepth ?? 0) }}</div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Fila dados (agente)
              </div>
              <div>{{ formatCount(agent.agentDataQueueDepth ?? 0) }}</div>
            </div>
          </div>

          <div class="grid gap-2 text-sm text-slate-300 md:grid-cols-2 lg:grid-cols-3">
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                CPU do agente
              </div>
              <div>
                {{
                  agent.agentCpuPercent != null
                    ? formatPercent(agent.agentCpuPercent)
                    : "-"
                }}
              </div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Memória (RSS)
              </div>
              <div>
                {{
                  agent.agentRssBytes && agent.agentRssBytes > 0
                    ? formatBytes(agent.agentRssBytes)
                    : "-"
                }}
              </div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
              <div class="text-xs uppercase tracking-wide text-slate-500">
                Goroutines
              </div>
              <div>
                {{
                  agent.agentGoroutines != null
                    ? formatCount(agent.agentGoroutines)
                    : "-"
                }}
              </div>
            </div>
          </div>

          <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
            <div class="text-xs uppercase tracking-wide text-slate-500">
              Destinos permitidos
            </div>
            <div v-if="agent.acl?.length" class="mt-2 space-y-1 font-mono text-xs text-slate-200">
              <div v-for="pattern in agent.acl" :key="pattern">
                {{ pattern }}
              </div>
            </div>
            <div v-else class="mt-2 text-xs text-slate-500">
              Sem restrições adicionais.
            </div>
          </div>

          <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-4">
            <div class="text-xs uppercase tracking-wide text-slate-500 mb-2">
              Streams ativas
            </div>
            <div v-if="agent.streams?.length">
              <div v-if="streamsForDisplay(agent).length" class="overflow-x-auto">
                <table class="min-w-full divide-y divide-slate-800 text-sm">
                  <thead class="text-slate-400">
                    <tr>
                      <th class="px-3 py-2 text-left font-medium">Stream ID</th>
                      <th class="px-3 py-2 text-left font-medium">Destino</th>
                      <th class="px-3 py-2 text-left font-medium">Protocolo</th>
                      <th class="px-3 py-2 text-left font-medium">Criada</th>
                      <th class="px-3 py-2 text-left font-medium">⬆</th>
                      <th class="px-3 py-2 text-left font-medium">⬇</th>
                      <th class="px-3 py-2 text-left font-medium">Fila ⬇</th>
                      <!-- <th class="px-3 py-2 text-left font-medium">Chunks em fila</th> -->
                      <!-- <th class="px-3 py-2 text-left font-medium">Limite fila</th> -->
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-slate-800">
                    <tr v-for="stream in streamsForDisplay(agent)" :key="stream.streamId" class="hover:bg-slate-900/80">
                      <td class="px-3 py-2 font-mono text-xs text-slate-200">
                        {{ stream.streamId }}
                      </td>
                      <td class="px-3 py-2 font-mono text-xs text-slate-300">
                        <div>{{ stream.target }}</div>
                        <div v-if="stream.resolvedTarget" class="mt-1 text-[11px] text-slate-500">
                          {{ stream.resolvedTarget }}
                          <span v-if="stream.resolutionSource">
                            · {{ resolutionSourceLabel(stream.resolutionSource) }}
                          </span>
                        </div>
                        <div
                          v-if="stream.groupName || stream.profileName || stream.principalName"
                          class="mt-1 text-[11px] text-slate-500"
                        >
                          <span v-if="stream.principalName">
                            {{ stream.principalType || "principal" }}: {{ stream.principalName }}
                          </span>
                          <span v-if="stream.groupName">
                            · grupo: {{ stream.groupName }}
                          </span>
                          <span v-if="stream.profileName">
                            · perfil: {{ stream.profileName }}
                          </span>
                        </div>
                        <div v-if="stream.routeReasonCode" class="mt-1 font-mono text-[11px] text-slate-600">
                          {{ stream.routeReasonCode }}
                        </div>
                        <div v-if="stream.routeReason" class="mt-1 text-[11px] text-slate-600">
                          {{ stream.routeReason }}
                        </div>
                      </td>
                      <td class="px-3 py-2 uppercase text-xs text-slate-200">
                        {{ stream.protocol }}
                      </td>
                      <td class="px-3 py-2 text-xs text-slate-300">
                        {{ formatRelative(stream.createdAt) }}
                      </td>
                      <td class="px-3 py-2 text-xs text-slate-300">
                        {{ formatBytes(stream.bytesUp) }}
                      </td>
                      <td class="px-3 py-2 text-xs text-slate-300">
                        {{ formatBytes(stream.bytesDown) }}
                      </td>
                      <td class="px-3 py-2 text-xs text-slate-300">
                        {{ formatBytes(stream.pendingClientBytes ?? 0) }}
                      </td>
                      <!-- <td class="px-3 py-2 text-xs text-slate-300">
                        {{ formatCount(stream.pendingClientChunks ?? 0) }}
                      </td> -->
                      <!-- <td class="px-3 py-2 text-xs text-slate-300">
                        {{ formatBytes(stream.clientBacklogLimit ?? 0) }}
                      </td> -->
                    </tr>
                  </tbody>
                </table>
              </div>
              <div v-else
                class="rounded-lg border border-dashed border-slate-800 bg-slate-900/80 p-4 text-sm text-slate-400">
                Nenhum destino correspondente.
              </div>
            </div>
            <div v-else
              class="rounded-lg border border-dashed border-slate-800 bg-slate-900/80 p-4 text-sm text-slate-400">
              Nenhum fluxo ativo
            </div>
          </div>
        </div>
      </article>
    </div>
    <div v-else class="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 p-6 text-center text-slate-400">
      Nenhum agente encontrado.
    </div>
  </section>
</template>
