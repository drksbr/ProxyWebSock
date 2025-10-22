<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{
  proxyAddr: string;
  secureAddr: string;
  socksAddr: string;
  acmeHosts: string[];
  backendVersion: string;
  frontendVersion: string;
}>();

const acmeLabel = computed(() => {
  return props.acmeHosts.length ? props.acmeHosts.join(" ") : "-";
});

const versionMismatch = computed(() => {
  return (
    props.backendVersion &&
    props.frontendVersion &&
    props.backendVersion !== props.frontendVersion
  );
});
</script>

<template>
  <header class="space-y-4">
    <div class="flex items-center gap-4">
      <img class="h-15" src="/logo-white.svg" alt="Intratun Relay" />
      <h1 class="text-3xl font-semibold tracking-tight">Intra Relay</h1>
    </div>
    <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
        <div class="text-sm text-slate-400">Proxy (HTTP CONNECT)</div>
        <div class="mt-1 font-mono text-lg">
          {{ proxyAddr || "desabilitado" }}
        </div>
      </div>
      <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
        <div class="text-sm text-slate-400">Secure (WSS / Metrics)</div>
        <div class="mt-1 font-mono text-lg">
          {{ secureAddr || "-" }}
        </div>
      </div>
      <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
        <div class="text-sm text-slate-400">SOCKS5</div>
        <div class="mt-1 font-mono text-lg">
          {{ socksAddr || "desabilitado" }}
        </div>
      </div>
    </div>
    <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
      <div class="mb-2 text-sm text-slate-400">ACME Hosts</div>
      <div class="font-mono text-sm">
        {{ acmeLabel }}
      </div>
    </div>
    <div
      class="rounded-lg border border-slate-800 bg-slate-900/60 p-4"
      :class="versionMismatch ? 'border-amber-500/50' : ''"
    >
      <div class="mb-2 text-sm text-slate-400">Versões</div>
      <div class="space-y-1 text-sm">
        <div>
          Backend:
          <span class="font-mono text-slate-100">{{ backendVersion || '-' }}</span>
        </div>
        <div>
          Frontend:
          <span class="font-mono text-slate-100">{{ frontendVersion }}</span>
        </div>
        <div
          v-if="versionMismatch"
          class="text-xs font-semibold uppercase tracking-wide text-amber-300"
        >
          Versões divergentes — atualize o frontend
        </div>
      </div>
    </div>
  </header>
</template>
