<script setup lang="ts">
import { computed } from "vue";

import { formatAbsolute } from "../../utils/format";

const props = defineProps<{
  generatedAt: string;
  summaryCards: { label: string; value: string; severity?: "normal" | "warn" | "danger" }[];
  alerts?: { message: string; severity: "warn" | "danger" }[];
}>();

const generatedAtLabel = computed(() => formatAbsolute(props.generatedAt));

function cardValueClass(severity?: string): string {
  switch (severity) {
    case "danger":
      return "text-rose-300";
    case "warn":
      return "text-amber-300";
    default:
      return "text-slate-100";
  }
}

function cardBorderClass(severity?: string): string {
  switch (severity) {
    case "danger":
      return "border-rose-500/30 bg-slate-900/60";
    case "warn":
      return "border-amber-500/30 bg-slate-900/60";
    default:
      return "border-slate-800 bg-slate-900/60";
  }
}
</script>

<template>
  <section>
    <!-- Alert banners -->
    <div v-if="alerts?.length" class="mb-4 space-y-2">
      <div
        v-for="(alert, i) in alerts"
        :key="i"
        class="flex items-center gap-3 rounded-lg border px-4 py-3 text-sm font-medium"
        :class="
          alert.severity === 'danger'
            ? 'border-rose-500/40 bg-rose-500/10 text-rose-200'
            : 'border-amber-500/40 bg-amber-500/10 text-amber-200'
        "
      >
        <span>⚠</span>
        {{ alert.message }}
      </div>
    </div>

    <div class="mb-4 flex items-center justify-between">
      <h2 class="text-xl font-semibold">Visão Geral</h2>
      <div class="text-sm text-slate-400">
        Atualizado
        <span class="font-medium text-slate-200">{{ generatedAtLabel }}</span>
      </div>
    </div>

    <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
      <div
        v-for="card in summaryCards"
        :key="card.label"
        class="rounded-lg border p-4 transition"
        :class="cardBorderClass(card.severity)"
      >
        <div class="text-xs font-medium uppercase tracking-wide text-slate-500">
          {{ card.label }}
        </div>
        <div class="mt-1.5 text-2xl font-semibold" :class="cardValueClass(card.severity)">
          {{ card.value }}
        </div>
      </div>
    </div>
  </section>
</template>
