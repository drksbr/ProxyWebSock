<script setup lang="ts">
import { computed, ref } from "vue";

import type { StatusDownload } from "../types/status";

const props = defineProps<{
  proxyAddr: string;
  secureAddr: string;
  socksAddr: string;
  acmeHosts: string[];
  downloads: StatusDownload[];
  backendVersion: string;
  frontendVersion: string;
  refreshOptions: readonly { label: string; ms: number }[];
  selectedInterval: number;
}>();

const emit = defineEmits<{
  (e: "update:refreshInterval", value: number): void;
}>();

const downloadsOpen = ref(false);
const refreshOpen = ref(false);

const versionMismatch = computed(() => {
  return (
    props.backendVersion &&
    props.frontendVersion &&
    props.backendVersion !== props.frontendVersion
  );
});

const selectedRefreshLabel = computed(() => {
  const match = props.refreshOptions.find((o) => o.ms === props.selectedInterval);
  if (match) return match.label;
  const s = props.selectedInterval / 1000;
  return s < 1 ? `${s.toFixed(2)}s` : `${s.toFixed(1)}s`;
});

function handleRefreshSelect(ms: number) {
  emit("update:refreshInterval", ms);
  refreshOpen.value = false;
}

function closeDownloads() {
  setTimeout(() => { downloadsOpen.value = false; }, 150);
}
function closeRefresh() {
  setTimeout(() => { refreshOpen.value = false; }, 150);
}
</script>

<template>
  <header class="sticky top-0 z-40 border-b border-slate-800 bg-slate-950/95 backdrop-blur">
    <div class="mx-auto flex max-w-7xl items-center gap-3 px-4 py-3">
      <!-- Logo + Nome -->
      <div class="flex shrink-0 items-center gap-2">
        <img class="h-7" src="/logo-white.svg" alt="Intratun Relay" />
        <span class="text-sm font-semibold tracking-tight text-slate-100">Intra Relay</span>
      </div>

      <!-- Endereços inline (ocultos em mobile) -->
      <div class="hidden items-center gap-1.5 md:flex">
        <span
          v-if="proxyAddr"
          class="rounded-full border border-slate-700/80 bg-slate-900 px-2.5 py-0.5 font-mono text-xs text-slate-400"
          title="Proxy HTTP CONNECT"
        >proxy {{ proxyAddr }}</span>
        <span
          v-if="secureAddr"
          class="rounded-full border border-slate-700/80 bg-slate-900 px-2.5 py-0.5 font-mono text-xs text-slate-400"
          title="Secure WSS / Metrics"
        >secure {{ secureAddr }}</span>
        <span
          v-if="socksAddr"
          class="rounded-full border border-slate-700/80 bg-slate-900 px-2.5 py-0.5 font-mono text-xs text-slate-400"
          title="SOCKS5"
        >socks {{ socksAddr }}</span>
      </div>

      <div class="flex-1" />

      <!-- Downloads dropdown -->
      <div class="relative">
        <button
          type="button"
          class="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:border-slate-500 hover:text-white"
          @click="downloadsOpen = !downloadsOpen"
          @blur="closeDownloads"
        >
          ↓ Agente
          <span :class="downloadsOpen ? 'inline-block rotate-180 transition-transform' : 'inline-block transition-transform'">▾</span>
        </button>
        <div
          v-if="downloadsOpen"
          class="absolute right-0 z-50 mt-2 w-64 overflow-hidden rounded-xl border border-slate-800 bg-slate-950 shadow-xl shadow-black/50"
        >
          <div class="border-b border-slate-800 px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            Downloads
          </div>
          <div v-if="downloads.length" class="max-h-72 space-y-0.5 overflow-y-auto p-2">
            <a
              v-for="d in downloads"
              :key="`${d.goos}-${d.goarch}`"
              :href="d.url"
              :download="d.fileName"
              class="flex items-center justify-between rounded-lg px-3 py-2 transition hover:bg-slate-800"
              @click="downloadsOpen = false"
            >
              <div>
                <div class="text-sm font-medium text-slate-100">{{ d.label }}</div>
                <div class="font-mono text-xs text-slate-500">{{ d.fileName }}</div>
              </div>
              <span v-if="d.version" class="text-xs text-cyan-300">{{ d.version }}</span>
            </a>
          </div>
          <div v-else class="p-4 text-center text-sm text-slate-500">
            Nenhum artefato disponível.
          </div>
          <div v-if="acmeHosts.length" class="border-t border-slate-800 px-4 py-2 font-mono text-xs text-slate-500">
            ACME: {{ acmeHosts.join(", ") }}
          </div>
        </div>
      </div>

      <!-- Refresh interval -->
      <div class="relative">
        <button
          type="button"
          class="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:border-slate-500 hover:text-white"
          @click="refreshOpen = !refreshOpen"
          @blur="closeRefresh"
        >
          <span>↻</span>
          <span class="font-mono">{{ selectedRefreshLabel }}</span>
          <span :class="refreshOpen ? 'inline-block rotate-180 transition-transform' : 'inline-block transition-transform'">▾</span>
        </button>
        <div
          v-if="refreshOpen"
          class="absolute right-0 z-50 mt-2 w-32 overflow-hidden rounded-xl border border-slate-800 bg-slate-950 shadow-xl shadow-black/50"
        >
          <button
            v-for="option in refreshOptions"
            :key="option.ms"
            type="button"
            class="flex w-full items-center justify-between px-3 py-2 text-left text-sm transition"
            :class="option.ms === selectedInterval ? 'bg-sky-500/20 text-sky-100' : 'text-slate-200 hover:bg-slate-800'"
            @click="handleRefreshSelect(option.ms)"
          >
            <span class="font-mono text-sm">{{ option.label }}</span>
            <span v-if="option.ms === selectedInterval" class="text-[10px] text-sky-300">ativo</span>
          </button>
        </div>
      </div>

      <!-- Version badge -->
      <div
        class="hidden shrink-0 rounded-md border px-2.5 py-1 text-xs sm:block"
        :class="versionMismatch ? 'border-amber-500/40 bg-amber-500/10 text-amber-300' : 'border-slate-800 text-slate-600'"
        :title="versionMismatch ? `Backend: ${backendVersion} / Frontend: ${frontendVersion}` : `v${backendVersion || frontendVersion}`"
      >
        <span v-if="versionMismatch">⚠ mismatch</span>
        <span v-else class="font-mono">{{ backendVersion || frontendVersion }}</span>
      </div>
    </div>
  </header>
</template>
