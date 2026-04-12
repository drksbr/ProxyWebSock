<script setup lang="ts">
import { computed } from "vue";

import type { StatusAuditEvent } from "../../types/status";
import { formatRelative } from "../../utils/format";
import { matchesSearch } from "../../utils/search";

const props = defineProps<{
  auditEvents: StatusAuditEvent[];
  searchQuery?: string;
  failuresOnly?: boolean;
}>();

const recentEvents = computed(() =>
  props.auditEvents
    .filter((event) => {
      if (props.failuresOnly && (event.outcome ?? "").toLowerCase() !== "failed") {
        return false;
      }
      return matchesSearch(props.searchQuery, [
        event.category,
        event.action,
        event.actorType,
        event.actorId,
        event.actorName,
        event.resourceType,
        event.resourceId,
        event.resourceName,
        event.outcome,
        event.message,
        event.remoteAddr,
        ...Object.keys(event.metadata ?? {}),
        ...Object.values(event.metadata ?? {}),
      ]);
    })
    .slice(0, 40),
);

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

function metadataSummary(event: StatusAuditEvent) {
  const entries = Object.entries(event.metadata ?? {}).filter(
    ([, value]) => value !== "",
  );
  return entries
    .slice(0, 3)
    .map(([key, value]) => `${key}: ${value}`)
    .join(" • ");
}
</script>

<template>
  <section class="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
    <div class="mb-4 flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">Auditoria Operacional</h2>
        <p class="mt-1 text-sm text-slate-400">
          Timeline persistente de mudanças de configuração, deployments e diagnósticos executados.
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
            <th class="px-4 py-3 text-left font-medium">Ação</th>
            <th class="px-4 py-3 text-left font-medium">Ator</th>
            <th class="px-4 py-3 text-left font-medium">Recurso</th>
            <th class="px-4 py-3 text-left font-medium">Resultado</th>
            <th class="px-4 py-3 text-left font-medium">Detalhes</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-800">
          <tr
            v-for="event in recentEvents"
            :key="event.id || `${event.timestamp}:${event.category}:${event.action}`"
            class="hover:bg-slate-900/80"
          >
            <td class="px-4 py-3 text-xs text-slate-300">
              {{ formatRelative(event.timestamp) }}
            </td>
            <td class="px-4 py-3 text-xs text-slate-300">
              <div class="font-medium">{{ event.action || "-" }}</div>
              <div class="mt-1 font-mono text-slate-500">
                {{ event.category || "-" }}
              </div>
            </td>
            <td class="px-4 py-3 text-xs text-slate-300">
              <div>{{ event.actorName || event.actorId || "dashboard" }}</div>
              <div class="mt-1 font-mono text-slate-500">
                {{ event.actorType || "-" }}
              </div>
            </td>
            <td class="px-4 py-3 text-xs text-slate-300">
              <div>{{ event.resourceName || event.resourceId || "-" }}</div>
              <div class="mt-1 font-mono text-slate-500">
                {{ event.resourceType || "-" }}
              </div>
            </td>
            <td class="px-4 py-3">
              <span
                class="rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide"
                :class="outcomeClasses(event.outcome)"
              >
                {{ event.outcome || "info" }}
              </span>
            </td>
            <td class="px-4 py-3 text-xs text-slate-300">
              <div>{{ event.message || "-" }}</div>
              <div v-if="metadataSummary(event)" class="mt-1 text-slate-500">
                {{ metadataSummary(event) }}
              </div>
              <div v-if="event.remoteAddr" class="mt-1 font-mono text-slate-600">
                {{ event.remoteAddr }}
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
      Nenhum evento de auditoria persistido ainda.
    </div>
  </section>
</template>
