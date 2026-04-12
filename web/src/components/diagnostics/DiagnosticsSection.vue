<script setup lang="ts">
import { computed, reactive, ref, watch } from "vue";

import type {
  DiagnosticRunRequest,
  DiagnosticRunResponse,
  DiagnosticStepResult,
} from "../../types/diagnostics";
import type {
  StatusAgent,
  StatusAgentGroup,
  StatusDestinationProfile,
  StatusDiagnosticEvent,
} from "../../types/status";
import { formatAbsolute, formatMillis, formatRelative } from "../../utils/format";
import { matchesSearch } from "../../utils/search";

type DiagnosticMode = "agent" | "group" | "profile";

const props = defineProps<{
  agents: StatusAgent[];
  agentGroups: StatusAgentGroup[];
  destinationProfiles: StatusDestinationProfile[];
  diagnosticEvents: StatusDiagnosticEvent[];
  searchQuery?: string;
  failuresOnly?: boolean;
}>();

const connectedAgents = computed(() =>
  props.agents.filter((agent) => agent.status !== "disconnected"),
);
const recentEvents = computed(() =>
  [...props.diagnosticEvents]
    .reverse()
    .filter((event) => {
      if (props.failuresOnly && (event.outcome ?? "").toLowerCase() !== "failed") {
        return false;
      }
      return matchesSearch(props.searchQuery, [
        event.mode,
        event.outcome,
        event.host,
        event.port,
        event.target,
        event.agentId,
        event.agentName,
        event.groupId,
        event.groupName,
        event.profileId,
        event.profileName,
        event.overrideAddress,
        event.reasonCode,
        event.message,
        event.selectedStatus,
      ]);
    })
    .slice(0, 12),
);

const mode = ref<DiagnosticMode>("agent");
const form = reactive({
  agentId: "",
  groupId: "",
  profileId: "",
  host: "",
  port: 443,
  tlsEnabled: true,
  tlsServerName: "",
  tlsSkipVerify: false,
  timeoutMs: 10000,
});

const running = ref(false);
const errorMessage = ref("");
const result = ref<DiagnosticRunResponse | null>(null);

const selectedProfile = computed(() =>
  props.destinationProfiles.find((profile) => profile.id === form.profileId),
);

watch(
  connectedAgents,
  (agents) => {
    if (!agents.length) {
      form.agentId = "";
      return;
    }
    if (!agents.some((agent) => agent.id === form.agentId)) {
      form.agentId = agents[0].id;
    }
  },
  { immediate: true },
);

watch(
  () => props.agentGroups,
  (groups) => {
    if (!groups.length) {
      form.groupId = "";
      return;
    }
    if (!groups.some((group) => group.id === form.groupId)) {
      form.groupId = groups[0].id;
    }
  },
  { deep: true, immediate: true },
);

watch(
  () => props.destinationProfiles,
  (profiles) => {
    if (!profiles.length) {
      form.profileId = "";
      return;
    }
    if (!profiles.some((profile) => profile.id === form.profileId)) {
      form.profileId = profiles[0].id;
    }
  },
  { deep: true, immediate: true },
);

watch(
  selectedProfile,
  (profile) => {
    if (!profile) return;
    form.host = profile.host;
    form.port = profile.port;
    if (!form.tlsServerName) {
      form.tlsServerName = profile.host;
    }
    if (profile.defaultGroupId) {
      form.groupId = profile.defaultGroupId;
    }
  },
  { immediate: true },
);

function agentLabel(agent: StatusAgent): string {
  if (agent.identification && agent.identification !== agent.id) {
    return `${agent.identification} (${agent.id})`;
  }
  return agent.id;
}

function groupLabel(group: StatusAgentGroup): string {
  return group.name || group.id;
}

function profileLabel(profile: StatusDestinationProfile): string {
  return `${profile.name} (${profile.host}:${profile.port})`;
}

function modeButtonClass(value: DiagnosticMode): string {
  const base = "rounded-full border px-3 py-1.5 text-sm font-medium transition";
  if (mode.value === value) {
    return `${base} border-sky-400 bg-sky-500/20 text-sky-100`;
  }
  return `${base} border-slate-700 text-slate-300 hover:border-slate-500 hover:text-slate-100`;
}

function stepCardClass(step: DiagnosticStepResult): string {
  const base = "rounded-xl border p-4";
  if (step.success) {
    return `${base} border-emerald-500/30 bg-emerald-500/5`;
  }
  return `${base} border-rose-500/30 bg-rose-500/10`;
}

function stepLabel(step: string): string {
  switch (step) {
    case "resolve":
      return "Resolve DNS";
    case "dial":
      return "Dial TCP";
    case "tls":
      return "Probe TLS";
    default:
      return step || "-";
  }
}

function outcomeClasses(outcome?: string) {
  switch ((outcome ?? "").toLowerCase()) {
    case "success":
      return "border border-emerald-500/30 bg-emerald-500/10 text-emerald-200";
    case "failed":
      return "border border-rose-500/30 bg-rose-500/10 text-rose-200";
    default:
      return "border border-slate-700 bg-slate-800/60 text-slate-300";
  }
}

function modeLabel(value?: string): string {
  switch (value) {
    case "agent":
      return "Agente";
    case "group":
      return "Grupo";
    case "profile":
      return "Perfil";
    default:
      return value || "-";
  }
}

async function runDiagnostic() {
  errorMessage.value = "";
  result.value = null;

  if (mode.value === "agent" && !form.agentId) {
    errorMessage.value = "Selecione um agente conectado.";
    return;
  }
  if (mode.value === "group" && !form.groupId) {
    errorMessage.value = "Selecione um grupo.";
    return;
  }
  if (mode.value === "profile" && !form.profileId) {
    errorMessage.value = "Selecione um perfil.";
    return;
  }
  if (mode.value !== "profile") {
    if (!form.host.trim()) {
      errorMessage.value = "Informe o host para diagnóstico.";
      return;
    }
    if (!Number.isFinite(form.port) || form.port <= 0 || form.port > 65535) {
      errorMessage.value = "A porta deve estar entre 1 e 65535.";
      return;
    }
  }

  running.value = true;
  try {
    const payload: DiagnosticRunRequest = {
      tlsEnabled: form.tlsEnabled,
      tlsServerName: form.tlsServerName?.trim() || "",
      tlsSkipVerify: form.tlsSkipVerify,
      timeoutMs: form.timeoutMs,
    };

    if (mode.value === "agent") {
      payload.agentId = form.agentId;
      payload.host = form.host.trim();
      payload.port = form.port;
    } else if (mode.value === "group") {
      payload.groupId = form.groupId;
      payload.host = form.host.trim();
      payload.port = form.port;
    } else {
      payload.profileId = form.profileId;
      if (form.groupId) {
        payload.groupId = form.groupId;
      }
    }

    const res = await fetch("/api/diagnostics", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const text = (await res.text()).trim();
      throw new Error(text || `HTTP ${res.status}`);
    }

    result.value = (await res.json()) as DiagnosticRunResponse;
  } catch (err) {
    errorMessage.value =
      err instanceof Error ? err.message : "Falha ao executar diagnóstico.";
  } finally {
    running.value = false;
  }
}
</script>

<template>
  <section class="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
    <div class="mb-4 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h2 class="text-xl font-semibold">Diagnóstico Ativo</h2>
        <p class="mt-1 text-sm text-slate-400">
          Executa resolução remota, dial TCP e probe TLS por agente direto, grupo com seleção automática ou perfil de destino.
        </p>
      </div>
      <div class="text-sm text-slate-500">
        {{ connectedAgents.length }} agentes conectados
      </div>
    </div>

    <div v-if="!connectedAgents.length" class="rounded-xl border border-dashed border-slate-800 bg-slate-950/50 p-6 text-center text-sm text-slate-400">
      Nenhum agente conectado no momento para executar diagnóstico.
    </div>

    <div v-else class="space-y-4">
      <div class="flex flex-wrap gap-2">
        <button type="button" :class="modeButtonClass('agent')" @click="mode = 'agent'">
          Agente
        </button>
        <button type="button" :class="modeButtonClass('group')" @click="mode = 'group'">
          Grupo
        </button>
        <button type="button" :class="modeButtonClass('profile')" @click="mode = 'profile'">
          Perfil
        </button>
      </div>

      <div class="grid gap-4 lg:grid-cols-3">
        <label v-if="mode === 'agent'" class="flex flex-col gap-2 text-sm font-medium text-slate-300">
          Agente
          <select
            v-model="form.agentId"
            class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
          >
            <option v-for="agent in connectedAgents" :key="agent.id" :value="agent.id">
              {{ agentLabel(agent) }}
            </option>
          </select>
        </label>

        <label v-if="mode === 'group'" class="flex flex-col gap-2 text-sm font-medium text-slate-300">
          Grupo
          <select
            v-model="form.groupId"
            class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
          >
            <option v-for="group in agentGroups" :key="group.id" :value="group.id">
              {{ groupLabel(group) }}
            </option>
          </select>
        </label>

        <label v-if="mode === 'profile'" class="flex flex-col gap-2 text-sm font-medium text-slate-300 lg:col-span-2">
          Perfil
          <select
            v-model="form.profileId"
            class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
          >
            <option v-for="profile in destinationProfiles" :key="profile.id" :value="profile.id">
              {{ profileLabel(profile) }}
            </option>
          </select>
        </label>

        <label v-if="mode === 'profile'" class="flex flex-col gap-2 text-sm font-medium text-slate-300">
          Grupo de execução
          <select
            v-model="form.groupId"
            class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
          >
            <option value="">usar padrão do perfil</option>
            <option v-for="group in agentGroups" :key="group.id" :value="group.id">
              {{ groupLabel(group) }}
            </option>
          </select>
        </label>
      </div>

      <div class="grid gap-4 lg:grid-cols-[minmax(0,1fr)_160px]">
        <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
          Host
          <input
            v-model="form.host"
            type="text"
            placeholder="aghuse.saude.ba.gov.br"
            class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400 disabled:opacity-60"
            :disabled="mode === 'profile'"
          />
        </label>

        <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
          Porta
          <input
            v-model.number="form.port"
            type="number"
            min="1"
            max="65535"
            class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400 disabled:opacity-60"
            :disabled="mode === 'profile'"
          />
        </label>
      </div>

      <div class="grid gap-4 lg:grid-cols-[160px_minmax(0,1fr)_160px]">
        <label class="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-sm text-slate-300">
          <input v-model="form.tlsEnabled" type="checkbox" class="h-4 w-4 rounded border-slate-600 bg-slate-950 text-sky-400 focus:ring-sky-400" />
          <span>Probe TLS</span>
        </label>

        <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
          SNI / Server Name
          <input
            v-model="form.tlsServerName"
            type="text"
            placeholder="opcional; padrão = host"
            class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            :disabled="!form.tlsEnabled"
          />
        </label>

        <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
          Timeout (ms)
          <input
            v-model.number="form.timeoutMs"
            type="number"
            min="1000"
            max="60000"
            step="500"
            class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
          />
        </label>
      </div>

      <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <label class="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-sm text-slate-300">
          <input v-model="form.tlsSkipVerify" type="checkbox" class="h-4 w-4 rounded border-slate-600 bg-slate-950 text-sky-400 focus:ring-sky-400" :disabled="!form.tlsEnabled" />
          <span>Ignorar validação do certificado</span>
        </label>

        <button
          type="button"
          class="rounded-lg border border-sky-500/50 bg-sky-500/15 px-4 py-2 text-sm font-semibold text-sky-100 transition hover:border-sky-400 hover:bg-sky-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          :disabled="running"
          @click="runDiagnostic"
        >
          {{ running ? "Executando..." : "Executar Diagnóstico" }}
        </button>
      </div>

      <div v-if="errorMessage" class="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
        {{ errorMessage }}
      </div>

      <div v-if="result" class="space-y-4 rounded-xl border border-slate-800 bg-slate-950/60 p-4">
        <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div class="space-y-1">
            <div class="flex items-center gap-2">
              <span
                :class="[
                  'rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide border',
                  result.success
                    ? 'border-emerald-400/40 bg-emerald-500/20 text-emerald-200'
                    : 'border-rose-500/30 bg-rose-500/10 text-rose-200',
                ]"
              >
                {{ result.success ? "Sucesso" : "Falha" }}
              </span>
              <span class="font-mono text-sm text-slate-300">
                {{ result.host }}:{{ result.port }}
              </span>
            </div>
            <div class="text-sm text-slate-400">
              modo: {{ modeLabel(result.mode) }}
              <span v-if="result.groupName"> · grupo: {{ result.groupName }}</span>
              <span v-if="result.profileName"> · perfil: {{ result.profileName }}</span>
            </div>
            <div class="text-sm text-slate-400">
              agente: {{ result.agentName || result.agentId || "-" }}
              <span v-if="result.selectedStatus"> · {{ result.selectedStatus }}</span>
              <span v-if="result.candidateCount"> · candidatos: {{ result.candidateCount }}</span>
            </div>
            <div v-if="result.overrideAddress" class="text-sm text-amber-300">
              Override aplicado: {{ result.overrideAddress }}
            </div>
            <div v-if="result.reasonCode || result.reason" class="text-sm text-slate-400">
              <span class="font-mono text-slate-200">{{ result.reasonCode || "-" }}</span>
              <span v-if="result.reason"> · {{ result.reason }}</span>
            </div>
            <div v-if="result.error" class="text-sm text-rose-200">
              {{ result.error }}
            </div>
          </div>

          <div class="grid gap-2 text-sm text-slate-400 sm:grid-cols-3">
            <div>
              <div class="text-slate-500">Início</div>
              <div class="font-mono text-slate-200">{{ formatAbsolute(result.startedAt || "") }}</div>
            </div>
            <div>
              <div class="text-slate-500">Fim</div>
              <div class="font-mono text-slate-200">{{ formatAbsolute(result.finishedAt || "") }}</div>
            </div>
            <div>
              <div class="text-slate-500">Duração</div>
              <div class="font-mono text-slate-200">{{ formatMillis(result.durationMillis || 0) }}</div>
            </div>
          </div>
        </div>

        <div class="grid gap-3 lg:grid-cols-3">
          <div v-for="step in result.steps" :key="`${step.step}:${step.selectedAddress}:${step.message}`" :class="stepCardClass(step)">
            <div class="mb-2 flex items-center justify-between">
              <h3 class="font-semibold text-slate-100">{{ stepLabel(step.step) }}</h3>
              <span
                :class="[
                  'rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide border',
                  step.success
                    ? 'border-emerald-400/40 bg-emerald-500/20 text-emerald-200'
                    : 'border-rose-500/30 bg-rose-500/10 text-rose-200',
                ]"
              >
                {{ step.success ? "ok" : "falhou" }}
              </span>
            </div>

            <div class="space-y-1 text-sm text-slate-300">
              <div v-if="step.durationMillis" class="text-slate-400">
                tempo: <span class="font-mono text-slate-200">{{ formatMillis(step.durationMillis) }}</span>
              </div>
              <div v-if="step.message">{{ step.message }}</div>
              <div v-if="step.resolutionSource" class="text-slate-400">
                origem: <span class="font-mono text-slate-200">{{ step.resolutionSource }}</span>
              </div>
              <div v-if="step.addresses?.length" class="text-slate-400">
                endereços:
                <span class="font-mono text-slate-200">{{ step.addresses.join(", ") }}</span>
              </div>
              <div v-if="step.selectedAddress" class="text-slate-400">
                alvo:
                <span class="font-mono text-slate-200">{{ step.selectedAddress }}</span>
              </div>
              <div v-if="step.tlsServerName" class="text-slate-400">
                sni:
                <span class="font-mono text-slate-200">{{ step.tlsServerName }}</span>
              </div>
              <div v-if="step.tlsVersion" class="text-slate-400">
                tls:
                <span class="font-mono text-slate-200">{{ step.tlsVersion }}</span>
              </div>
              <div v-if="step.tlsCipherSuite" class="text-slate-400">
                cipher:
                <span class="font-mono text-slate-200">{{ step.tlsCipherSuite }}</span>
              </div>
              <div v-if="step.tlsPeerNames?.length" class="text-slate-400">
                peer names:
                <span class="font-mono text-slate-200">{{ step.tlsPeerNames.join(", ") }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
        <div class="mb-3 flex items-center justify-between">
          <div>
            <h3 class="font-semibold text-slate-100">Histórico Recente</h3>
            <p class="mt-1 text-sm text-slate-400">
              Últimos diagnósticos executados no relay.
            </p>
          </div>
          <div class="text-sm text-slate-500">{{ recentEvents.length }} eventos</div>
        </div>

        <div v-if="recentEvents.length" class="overflow-x-auto">
          <table class="min-w-full divide-y divide-slate-800 text-sm">
            <thead class="text-slate-400">
              <tr>
                <th class="px-3 py-2 text-left font-medium">Quando</th>
                <th class="px-3 py-2 text-left font-medium">Modo</th>
                <th class="px-3 py-2 text-left font-medium">Destino</th>
                <th class="px-3 py-2 text-left font-medium">Grupo / Perfil</th>
                <th class="px-3 py-2 text-left font-medium">Agente</th>
                <th class="px-3 py-2 text-left font-medium">Resultado</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800">
              <tr v-for="event in recentEvents" :key="`${event.timestamp}:${event.target}:${event.mode}:${event.outcome}`" class="hover:bg-slate-900/80">
                <td class="px-3 py-2 text-xs text-slate-300">
                  {{ formatRelative(event.timestamp) }}
                </td>
                <td class="px-3 py-2 text-xs text-slate-300">
                  <div>{{ modeLabel(event.mode) }}</div>
                  <div v-if="event.reasonCode" class="mt-1 font-mono text-slate-500">
                    {{ event.reasonCode }}
                  </div>
                </td>
                <td class="px-3 py-2 text-xs text-slate-300">
                  <div class="font-mono">{{ event.target }}</div>
                  <div v-if="event.overrideAddress" class="mt-1 text-amber-300">
                    override {{ event.overrideAddress }}
                  </div>
                </td>
                <td class="px-3 py-2 text-xs text-slate-300">
                  <div v-if="event.groupName">{{ event.groupName }}</div>
                  <div v-if="event.profileName" class="mt-1 text-slate-500">
                    {{ event.profileName }}
                  </div>
                  <div v-if="event.candidateCount" class="mt-1 text-slate-600">
                    candidatos: {{ event.candidateCount }}
                  </div>
                </td>
                <td class="px-3 py-2 text-xs text-slate-300">
                  <div>{{ event.agentName || event.agentId || "-" }}</div>
                  <div v-if="event.selectedStatus" class="mt-1 text-slate-500">
                    {{ event.selectedStatus }}
                  </div>
                </td>
                <td class="px-3 py-2 text-xs text-slate-300">
                  <div class="flex items-center gap-2">
                    <span class="rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide" :class="outcomeClasses(event.outcome)">
                      {{ event.outcome || "unknown" }}
                    </span>
                    <span class="font-mono text-slate-500">{{ formatMillis(event.durationMillis || 0) }}</span>
                  </div>
                  <div v-if="event.message" class="mt-1 text-slate-500">
                    {{ event.message }}
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div v-else class="rounded-lg border border-dashed border-slate-800 bg-slate-900/40 p-4 text-center text-sm text-slate-400">
          Nenhum diagnóstico executado ainda.
        </div>
      </div>
    </div>
  </section>
</template>
