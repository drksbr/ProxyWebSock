<script setup lang="ts">
import { computed } from "vue";

import type { StatusRouteEvent } from "../../types/status";
import { formatRelative } from "../../utils/format";
import { matchesSearch } from "../../utils/search";

const props = defineProps<{
  routeEvents: StatusRouteEvent[];
  searchQuery?: string;
  failuresOnly?: boolean;
}>();

const recentEvents = computed(() =>
  [...props.routeEvents]
    .reverse()
    .filter((event) => {
      if (props.failuresOnly && (event.outcome ?? "").toLowerCase() !== "failed") {
        return false;
      }
      return matchesSearch(props.searchQuery, [
        event.timestamp,
        event.protocol,
        event.outcome,
        event.reasonCode,
        event.message,
        event.target,
        event.principalType,
        event.principalName,
        event.groupId,
        event.groupName,
        event.profileId,
        event.profileName,
        event.agentId,
        event.agentName,
        event.selectedStatus,
      ]);
    })
    .slice(0, 30),
);

function outcomeClasses(outcome?: string) {
  switch ((outcome ?? "").toLowerCase()) {
    case "selected":
      return "border border-emerald-500/30 bg-emerald-500/10 text-emerald-200";
    case "failed":
      return "border border-rose-500/30 bg-rose-500/10 text-rose-200";
    default:
      return "border border-slate-700 bg-slate-800/60 text-slate-300";
  }
}
</script>

<template>
  <section class="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
    <div class="mb-4 flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">Roteamento Recente</h2>
        <p class="mt-1 text-sm text-slate-400">
          Histórico recente de decisões e falhas de seleção de agente no relay.
        </p>
      </div>
      <div class="text-sm text-slate-500">
        {{ recentEvents.length }} eventos
      </div>
    </div>

    <div
      v-if="recentEvents.length"
      class="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/60"
    >
      <table class="min-w-full divide-y divide-slate-800 text-sm">
        <thead class="text-slate-400">
          <tr>
            <th class="px-4 py-3 text-left font-medium">Quando</th>
            <th class="px-4 py-3 text-left font-medium">Resultado</th>
            <th class="px-4 py-3 text-left font-medium">Principal</th>
            <th class="px-4 py-3 text-left font-medium">Destino</th>
            <th class="px-4 py-3 text-left font-medium">Grupo / Perfil</th>
            <th class="px-4 py-3 text-left font-medium">Agente</th>
            <th class="px-4 py-3 text-left font-medium">Diagnóstico</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-800">
          <tr v-for="event in recentEvents" :key="`${event.timestamp}:${event.target}:${event.reasonCode}:${event.outcome}`" class="hover:bg-slate-900/80">
            <td class="px-4 py-3 text-xs text-slate-300">
              {{ formatRelative(event.timestamp) }}
            </td>
            <td class="px-4 py-3">
              <div class="flex flex-col gap-1">
                <span
                  class="rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide"
                  :class="outcomeClasses(event.outcome)"
                >
                  {{ event.outcome || "unknown" }}
                </span>
                <span class="font-mono text-[11px] text-slate-500">
                  {{ event.protocol || "-" }}
                </span>
              </div>
            </td>
            <td class="px-4 py-3 text-xs text-slate-300">
              <div>{{ event.principalName || "-" }}</div>
              <div class="mt-1 font-mono text-slate-500">
                {{ event.principalType || "-" }}
              </div>
            </td>
            <td class="px-4 py-3 font-mono text-xs text-slate-300">
              {{ event.target }}
            </td>
            <td class="px-4 py-3 text-xs text-slate-300">
              <div v-if="event.groupName">{{ event.groupName }}</div>
              <div v-if="event.profileName" class="mt-1 text-slate-500">
                {{ event.profileName }}
              </div>
              <div v-if="event.candidateCount" class="mt-1 text-slate-600">
                candidatos: {{ event.candidateCount }}
              </div>
            </td>
            <td class="px-4 py-3 text-xs text-slate-300">
              <div>{{ event.agentName || event.agentId || "-" }}</div>
              <div v-if="event.selectedStatus" class="mt-1 text-slate-500">
                {{ event.selectedStatus }}
              </div>
            </td>
            <td class="px-4 py-3 text-xs text-slate-300">
              <div class="font-mono text-slate-400">
                {{ event.reasonCode || "-" }}
              </div>
              <div v-if="event.message" class="mt-1 text-slate-500">
                {{ event.message }}
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div
      v-else
      class="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 p-6 text-center text-sm text-slate-400"
    >
      Nenhum evento de roteamento registrado ainda.
    </div>
  </section>
</template>
