<script setup lang="ts">
import { ref } from "vue";

import AuditSection from "../audit/AuditSection.vue";
import RoutingSection from "../routing/RoutingSection.vue";
import SupportSection from "../support/SupportSection.vue";
import type {
  StatusAuditEvent,
  StatusRouteEvent,
  StatusSupportSnapshot,
} from "../../types/status";

type EventTab = "support" | "routing" | "audit";

defineProps<{
  support: StatusSupportSnapshot;
  routeEvents: StatusRouteEvent[];
  auditEvents: StatusAuditEvent[];
}>();

const activeEventTab = ref<EventTab>("support");
const searchQuery = ref("");
const failuresOnly = ref(false);

function tabClass(tab: EventTab): string {
  const base =
    "whitespace-nowrap px-4 py-2.5 text-sm font-medium border-b-2 transition -mb-px";
  if (activeEventTab.value === tab) {
    return `${base} border-sky-400 text-sky-100`;
  }
  return `${base} border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-600`;
}
</script>

<template>
  <section class="space-y-4">
    <!-- Filtro compartilhado -->
    <div
      class="flex flex-wrap items-center gap-3 rounded-xl border border-slate-800 bg-slate-900/40 px-4 py-3"
    >
      <input
        v-model="searchQuery"
        type="search"
        placeholder="Filtrar eventos: host, usuário, agente, grupo, código de motivo..."
        class="min-w-48 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
      />
      <label class="flex cursor-pointer select-none items-center gap-2 text-sm text-slate-300">
        <input
          v-model="failuresOnly"
          type="checkbox"
          class="h-4 w-4 rounded border-slate-600 bg-slate-950 text-sky-400 focus:ring-sky-400"
        />
        Somente falhas
      </label>
      <button
        v-if="searchQuery || failuresOnly"
        type="button"
        class="text-xs font-semibold uppercase tracking-wide text-slate-400 hover:text-slate-200"
        @click="
          searchQuery = '';
          failuresOnly = false;
        "
      >
        Limpar
      </button>
    </div>

    <!-- Sub-tabs -->
    <div class="border-b border-slate-800">
      <nav class="flex gap-0 overflow-x-auto">
        <button type="button" :class="tabClass('support')" @click="activeEventTab = 'support'">
          Suporte Operacional
        </button>
        <button type="button" :class="tabClass('routing')" @click="activeEventTab = 'routing'">
          Roteamento
        </button>
        <button type="button" :class="tabClass('audit')" @click="activeEventTab = 'audit'">
          Auditoria
        </button>
      </nav>
    </div>

    <!-- Conteúdo -->
    <SupportSection
      v-if="activeEventTab === 'support'"
      :support="support"
      :search-query="searchQuery"
      :failures-only="failuresOnly"
      :hide-filter="true"
      @update:search-query="searchQuery = $event"
      @update:failures-only="failuresOnly = $event"
    />
    <RoutingSection
      v-if="activeEventTab === 'routing'"
      :route-events="routeEvents"
      :search-query="searchQuery"
      :failures-only="failuresOnly"
    />
    <AuditSection
      v-if="activeEventTab === 'audit'"
      :audit-events="auditEvents"
      :search-query="searchQuery"
      :failures-only="failuresOnly"
    />
  </section>
</template>
