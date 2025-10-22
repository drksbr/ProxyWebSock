<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{
  proxyAddr: string;
  secureAddr: string;
  socksAddr: string;
  acmeHosts: string[];
}>();

const acmeLabel = computed(() => {
  return props.acmeHosts.length ? props.acmeHosts.join(" ") : "-";
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
  </header>
</template>
