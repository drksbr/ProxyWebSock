<script setup lang="ts">
import { computed, ref } from "vue";

import { formatAbsolute } from "../../utils/format";

const props = defineProps<{
  generatedAt: string;
  refreshOptions: readonly { label: string; ms: number }[];
  selectedInterval: number;
  summaryCards: { label: string; value: string }[];
}>();

const emit = defineEmits<{
  (e: "update:refreshInterval", value: number): void;
}>();

const refreshMenuOpen = ref(false);

const generatedAtLabel = computed(() => formatAbsolute(props.generatedAt));

const selectedRefreshLabel = computed(() => {
  const match = props.refreshOptions.find(
    (option) => option.ms === props.selectedInterval,
  );
  if (match) {
    return match.label;
  }
  const seconds = props.selectedInterval / 1000;
  return seconds < 1 ? `${seconds.toFixed(2)}s` : `${seconds.toFixed(1)}s`;
});

function handleSelect(ms: number) {
  emit("update:refreshInterval", ms);
  refreshMenuOpen.value = false;
}
</script>

<template>
  <section>
    <div
      class="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between"
    >
      <h2 class="text-xl font-semibold">Resumo</h2>
      <div
        class="flex flex-col items-start gap-2 text-sm text-slate-400 sm:flex-row sm:items-center sm:gap-4"
      >
        <div>
          Atualizado
          <span class="font-medium text-slate-200">{{ generatedAtLabel }}</span>
        </div>
        <div class="relative">
          <button
            type="button"
            class="flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-xs font-medium uppercase tracking-wide text-slate-200 transition hover:border-slate-500 hover:text-slate-100"
            @click="refreshMenuOpen = !refreshMenuOpen"
            @keydown.escape="refreshMenuOpen = false"
          >
            <span class="text-[11px] font-semibold text-slate-400"
              >Atualizar a cada</span
            >
            <span class="font-mono text-sm text-slate-100">{{
              selectedRefreshLabel
            }}</span>
            <span
              class="text-slate-500"
              :class="
                refreshMenuOpen
                  ? 'rotate-180 transform transition'
                  : 'transition'
              "
              >▾</span
            >
          </button>
          <div
            v-if="refreshMenuOpen"
            class="absolute right-0 z-10 mt-2 w-40 overflow-hidden rounded-lg border border-slate-800 bg-slate-950/95 shadow-lg shadow-slate-950/40 backdrop-blur"
          >
            <button
              v-for="option in refreshOptions"
              :key="option.ms"
              type="button"
              class="flex w-full items-center justify-between px-3 py-2 text-left text-sm transition"
              :class="
                option.ms === selectedInterval
                  ? 'bg-sky-500/20 text-sky-100'
                  : 'text-slate-200 hover:bg-slate-900/80'
              "
              @click="handleSelect(option.ms)"
            >
              <span class="font-mono text-sm">{{ option.label }}</span>
              <span
                v-if="option.ms === selectedInterval"
                class="text-xs text-sky-200"
                >ativo</span
              >
            </button>
          </div>
        </div>
      </div>
    </div>
    <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
      <div
        v-for="card in summaryCards"
        :key="card.label"
        class="rounded-lg border border-slate-800 bg-slate-900/60 p-4"
      >
        <div class="text-sm text-slate-400">{{ card.label }}</div>
        <div class="mt-1 text-2xl font-semibold text-slate-100">
          {{ card.value }}
        </div>
      </div>
    </div>
  </section>
</template>
