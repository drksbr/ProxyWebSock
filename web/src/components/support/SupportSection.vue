<script setup lang="ts">
import type {
  StatusCircuitBreaker,
  StatusQuotaCounter,
  StatusSupportBucket,
  StatusSupportSnapshot,
} from "../../types/status";
import { formatAbsolute, formatRelative } from "../../utils/format";

defineProps<{
  support: StatusSupportSnapshot;
  searchQuery: string;
  failuresOnly: boolean;
  hideFilter?: boolean;
}>();

const emit = defineEmits<{
  "update:searchQuery": [value: string];
  "update:failuresOnly": [value: boolean];
}>();

function applyFilter(value: string) {
  emit("update:searchQuery", value);
  emit("update:failuresOnly", true);
}

function bucketSourceLabel(bucket: StatusSupportBucket): string {
  const sources = bucket.sources ?? [];
  if (!sources.length) return "-";
  return sources.join(" + ");
}

function breakerBadgeClasses(breaker: StatusCircuitBreaker): string {
  switch ((breaker.state ?? "").toLowerCase()) {
    case "open":
      return "border border-rose-500/30 bg-rose-500/10 text-rose-200";
    case "half-open":
      return "border border-amber-500/30 bg-amber-500/10 text-amber-200";
    default:
      return "border border-slate-700 bg-slate-800/60 text-slate-300";
  }
}

function quotaBadgeClasses(counter: StatusQuotaCounter): string {
  if (counter.saturated) {
    return "border border-amber-500/30 bg-amber-500/10 text-amber-200";
  }
  return "border border-slate-700 bg-slate-800/60 text-slate-300";
}
</script>

<template>
  <section class="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
    <div class="mb-4 flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
      <div>
        <h2 class="text-xl font-semibold">Suporte Operacional</h2>
        <p class="mt-1 text-sm text-slate-400">
          Breakdown recente de falhas por destino, usuário/principal e agente, com filtro compartilhado das timelines.
        </p>
      </div>
      <div class="grid gap-2 text-sm text-slate-400 sm:grid-cols-3">
        <div class="rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2">
          <div class="text-slate-500">Falhas totais</div>
          <div class="text-lg font-semibold text-slate-100">{{ support.totalFailures || 0 }}</div>
        </div>
        <div class="rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2">
          <div class="text-slate-500">Falhas de rota</div>
          <div class="text-lg font-semibold text-slate-100">{{ support.routeFailures || 0 }}</div>
        </div>
        <div class="rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2">
          <div class="text-slate-500">Falhas de diagnóstico</div>
          <div class="text-lg font-semibold text-slate-100">{{ support.diagnosticFailures || 0 }}</div>
        </div>
      </div>
    </div>

    <div v-if="!hideFilter" class="mb-4 grid gap-3 lg:grid-cols-[minmax(0,1fr)_220px_120px]">
      <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
        Filtro compartilhado
        <input
          :value="searchQuery"
          type="text"
          placeholder="host, usuario, agente, grupo, reason code..."
          class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
          @input="emit('update:searchQuery', ($event.target as HTMLInputElement).value)"
        />
      </label>

      <label class="flex items-end">
        <span class="flex w-full items-center gap-3 rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-sm text-slate-300">
          <input
            :checked="failuresOnly"
            type="checkbox"
            class="h-4 w-4 rounded border-slate-600 bg-slate-950 text-sky-400 focus:ring-sky-400"
            @change="emit('update:failuresOnly', ($event.target as HTMLInputElement).checked)"
          />
          Somente falhas
        </span>
      </label>

      <button
        type="button"
        class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200 transition hover:border-slate-500 hover:text-white"
        @click="
          emit('update:searchQuery', '');
          emit('update:failuresOnly', false);
        "
      >
        Limpar filtro
      </button>
    </div>

    <div class="grid gap-4 xl:grid-cols-3">
      <div class="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
        <div class="mb-3 flex items-center justify-between">
          <h3 class="font-semibold text-slate-100">Top destinos</h3>
          <span class="text-xs text-slate-500">{{ support.topDestinations?.length ?? 0 }} itens</span>
        </div>
        <div v-if="support.topDestinations?.length" class="space-y-2">
          <button
            v-for="bucket in support.topDestinations"
            :key="`target:${bucket.key}`"
            type="button"
            class="flex w-full items-start justify-between rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-left transition hover:border-sky-500/40 hover:bg-sky-500/5"
            @click="applyFilter(bucket.label)"
          >
            <div class="min-w-0">
              <div class="truncate font-mono text-xs text-slate-200">{{ bucket.label }}</div>
              <div class="mt-1 text-[11px] text-slate-500">
                {{ bucketSourceLabel(bucket) }} · {{ formatRelative(bucket.lastSeen || '') }}
              </div>
            </div>
            <div class="ml-3 rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[11px] font-semibold text-rose-200">
              {{ bucket.count }}
            </div>
          </button>
        </div>
        <div v-else class="rounded-lg border border-dashed border-slate-800 bg-slate-900/40 p-4 text-center text-sm text-slate-400">
          Nenhuma falha recente por destino.
        </div>
      </div>

      <div class="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
        <div class="mb-3 flex items-center justify-between">
          <h3 class="font-semibold text-slate-100">Top usuários / principais</h3>
          <span class="text-xs text-slate-500">{{ support.topPrincipals?.length ?? 0 }} itens</span>
        </div>
        <div v-if="support.topPrincipals?.length" class="space-y-2">
          <button
            v-for="bucket in support.topPrincipals"
            :key="`principal:${bucket.key}`"
            type="button"
            class="flex w-full items-start justify-between rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-left transition hover:border-sky-500/40 hover:bg-sky-500/5"
            @click="applyFilter(bucket.label)"
          >
            <div class="min-w-0">
              <div class="truncate text-sm text-slate-200">{{ bucket.label }}</div>
              <div class="mt-1 text-[11px] text-slate-500">
                {{ bucketSourceLabel(bucket) }} · {{ formatRelative(bucket.lastSeen || '') }}
              </div>
            </div>
            <div class="ml-3 rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[11px] font-semibold text-rose-200">
              {{ bucket.count }}
            </div>
          </button>
        </div>
        <div v-else class="rounded-lg border border-dashed border-slate-800 bg-slate-900/40 p-4 text-center text-sm text-slate-400">
          Nenhuma falha recente associada a usuários/principais.
        </div>
      </div>

      <div class="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
        <div class="mb-3 flex items-center justify-between">
          <h3 class="font-semibold text-slate-100">Top agentes</h3>
          <span class="text-xs text-slate-500">{{ support.topAgents?.length ?? 0 }} itens</span>
        </div>
        <div v-if="support.topAgents?.length" class="space-y-2">
          <button
            v-for="bucket in support.topAgents"
            :key="`agent:${bucket.key}`"
            type="button"
            class="flex w-full items-start justify-between rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-left transition hover:border-sky-500/40 hover:bg-sky-500/5"
            @click="applyFilter(bucket.label)"
          >
            <div class="min-w-0">
              <div class="truncate text-sm text-slate-200">{{ bucket.label }}</div>
              <div class="mt-1 text-[11px] text-slate-500">
                {{ bucketSourceLabel(bucket) }} · {{ formatRelative(bucket.lastSeen || '') }}
              </div>
            </div>
            <div class="ml-3 rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[11px] font-semibold text-rose-200">
              {{ bucket.count }}
            </div>
          </button>
        </div>
        <div v-else class="rounded-lg border border-dashed border-slate-800 bg-slate-900/40 p-4 text-center text-sm text-slate-400">
          Nenhuma falha recente associada a agentes.
        </div>
      </div>
    </div>

    <div class="mt-4 rounded-xl border border-slate-800 bg-slate-950/60 p-4">
      <div class="mb-4">
        <h3 class="font-semibold text-slate-100">Quotas de Streams</h3>
        <p class="mt-1 text-sm text-slate-400">
          Limites concorrentes aplicados antes do dial para usuários, grupos e agentes.
        </p>
      </div>

      <div class="grid gap-4 xl:grid-cols-3">
        <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div class="mb-3 flex items-center justify-between">
            <h4 class="font-semibold text-slate-100">Usuários</h4>
            <span class="text-xs text-slate-500">
              limite {{ support.quotas?.userStreamLimit || 0 }}
            </span>
          </div>
          <div v-if="support.quotas?.users?.length" class="space-y-2">
            <div
              v-for="counter in support.quotas?.users"
              :key="`quota-user:${counter.key}`"
              class="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2"
            >
              <button
                type="button"
                class="truncate text-left text-sm text-slate-200 transition hover:text-sky-200"
                @click="applyFilter(counter.label)"
              >
                {{ counter.label }}
              </button>
              <span class="rounded-full px-2 py-0.5 text-[11px] font-semibold" :class="quotaBadgeClasses(counter)">
                {{ counter.count }}/{{ counter.limit || "∞" }}
              </span>
            </div>
          </div>
          <div v-else class="rounded-lg border border-dashed border-slate-800 bg-slate-900/40 p-4 text-center text-sm text-slate-400">
            Nenhum usuário com stream ativo.
          </div>
        </div>

        <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div class="mb-3 flex items-center justify-between">
            <h4 class="font-semibold text-slate-100">Grupos</h4>
            <span class="text-xs text-slate-500">
              limite {{ support.quotas?.groupStreamLimit || 0 }}
            </span>
          </div>
          <div v-if="support.quotas?.groups?.length" class="space-y-2">
            <div
              v-for="counter in support.quotas?.groups"
              :key="`quota-group:${counter.key}`"
              class="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2"
            >
              <button
                type="button"
                class="truncate text-left text-sm text-slate-200 transition hover:text-sky-200"
                @click="applyFilter(counter.label)"
              >
                {{ counter.label }}
              </button>
              <span class="rounded-full px-2 py-0.5 text-[11px] font-semibold" :class="quotaBadgeClasses(counter)">
                {{ counter.count }}/{{ counter.limit || "∞" }}
              </span>
            </div>
          </div>
          <div v-else class="rounded-lg border border-dashed border-slate-800 bg-slate-900/40 p-4 text-center text-sm text-slate-400">
            Nenhum grupo com stream ativo.
          </div>
        </div>

        <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div class="mb-3 flex items-center justify-between">
            <h4 class="font-semibold text-slate-100">Agentes</h4>
            <span class="text-xs text-slate-500">
              limite {{ support.quotas?.agentStreamLimit || 0 }}
            </span>
          </div>
          <div v-if="support.quotas?.agents?.length" class="space-y-2">
            <div
              v-for="counter in support.quotas?.agents"
              :key="`quota-agent:${counter.key}`"
              class="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2"
            >
              <button
                type="button"
                class="truncate text-left text-sm text-slate-200 transition hover:text-sky-200"
                @click="applyFilter(counter.label)"
              >
                {{ counter.label }}
              </button>
              <span class="rounded-full px-2 py-0.5 text-[11px] font-semibold" :class="quotaBadgeClasses(counter)">
                {{ counter.count }}/{{ counter.limit || "∞" }}
              </span>
            </div>
          </div>
          <div v-else class="rounded-lg border border-dashed border-slate-800 bg-slate-900/40 p-4 text-center text-sm text-slate-400">
            Nenhum agente com stream ativo.
          </div>
        </div>
      </div>
    </div>

    <div class="mt-4 rounded-xl border border-slate-800 bg-slate-950/60 p-4">
      <div class="mb-3 flex items-center justify-between">
        <h3 class="font-semibold text-slate-100">Circuit Breakers Ativos</h3>
        <span class="text-xs text-slate-500">{{ support.activeBreakers?.length ?? 0 }} itens</span>
      </div>

      <div v-if="support.activeBreakers?.length" class="overflow-x-auto">
        <table class="min-w-full divide-y divide-slate-800 text-sm">
          <thead class="text-slate-400">
            <tr>
              <th class="px-3 py-2 text-left font-medium">Estado</th>
              <th class="px-3 py-2 text-left font-medium">Destino</th>
              <th class="px-3 py-2 text-left font-medium">Grupo</th>
              <th class="px-3 py-2 text-left font-medium">Falhas</th>
              <th class="px-3 py-2 text-left font-medium">Cooldown</th>
              <th class="px-3 py-2 text-left font-medium">Último erro</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-800">
            <tr
              v-for="breaker in support.activeBreakers"
              :key="`${breaker.groupId}:${breaker.target}`"
              class="hover:bg-slate-900/80"
            >
              <td class="px-3 py-2">
                <span
                  class="rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide"
                  :class="breakerBadgeClasses(breaker)"
                >
                  {{ breaker.state || "-" }}
                </span>
              </td>
              <td class="px-3 py-2 text-xs text-slate-300">
                <button
                  type="button"
                  class="font-mono text-left text-slate-200 transition hover:text-sky-200"
                  @click="applyFilter(breaker.target)"
                >
                  {{ breaker.target }}
                </button>
              </td>
              <td class="px-3 py-2 text-xs text-slate-300">
                <div>{{ breaker.groupName || breaker.groupId || "-" }}</div>
              </td>
              <td class="px-3 py-2 text-xs text-slate-300">
                {{ breaker.consecutiveFailures || 0 }}
                <span v-if="breaker.probeInFlight" class="ml-2 text-amber-300">
                  probe
                </span>
              </td>
              <td class="px-3 py-2 text-xs text-slate-300">
                <div v-if="breaker.openUntil">
                  até {{ formatAbsolute(breaker.openUntil) }}
                </div>
                <div v-if="breaker.lastFailureAt" class="mt-1 text-slate-500">
                  última falha {{ formatRelative(breaker.lastFailureAt) }}
                </div>
              </td>
              <td class="px-3 py-2 text-xs text-slate-300">
                {{ breaker.lastError || "-" }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-else class="rounded-lg border border-dashed border-slate-800 bg-slate-900/40 p-4 text-center text-sm text-slate-400">
        Nenhum circuit breaker ativo no momento.
      </div>
    </div>
  </section>
</template>
