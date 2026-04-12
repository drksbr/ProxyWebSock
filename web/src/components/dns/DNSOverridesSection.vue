<script setup lang="ts">
import { computed, reactive, ref } from "vue";

import type { StatusDNSOverride } from "../../types/status";
import { formatAbsolute, formatRelative } from "../../utils/format";

const props = defineProps<{
  overrides: StatusDNSOverride[];
}>();

const emit = defineEmits<{
  (e: "refreshRequested"): void;
}>();

const form = reactive({
  host: "",
  address: "",
});
const saveBusy = ref(false);
const saveError = ref("");
const saveMessage = ref("");
const deletingHost = ref("");

const hasOverrides = computed(() => props.overrides.length > 0);

async function saveOverride() {
  saveBusy.value = true;
  saveError.value = "";
  saveMessage.value = "";
  try {
    const res = await fetch("/api/dns-overrides", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        host: form.host.trim(),
        address: form.address.trim(),
      }),
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    form.host = "";
    form.address = "";
    saveMessage.value = "Override salvo. Novos dials já passam a usar esse IP.";
    emit("refreshRequested");
  } catch (err) {
    saveError.value =
      err instanceof Error ? err.message : "Falha ao salvar override.";
  } finally {
    saveBusy.value = false;
  }
}

async function deleteOverride(host: string) {
  deletingHost.value = host;
  saveError.value = "";
  saveMessage.value = "";
  try {
    const res = await fetch(`/api/dns-overrides/${encodeURIComponent(host)}`, {
      method: "DELETE",
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    saveMessage.value = `Override ${host} removido.`;
    emit("refreshRequested");
  } catch (err) {
    saveError.value =
      err instanceof Error ? err.message : "Falha ao remover override.";
  } finally {
    deletingHost.value = "";
  }
}
</script>

<template>
  <section>
    <div class="mb-4 flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold">Overrides DNS</h2>
        <p class="mt-1 text-sm text-slate-400">
          O IP configurado aqui sobrepõe o DNS local do agente para novos acessos.
        </p>
      </div>
      <div class="text-sm text-slate-500">
        {{ overrides.length }} mapeamentos
      </div>
    </div>

    <div class="grid gap-4 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)_auto] rounded-xl border border-slate-800 bg-slate-900/40 p-4">
      <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
        Hostname
        <input
          v-model="form.host"
          type="text"
          placeholder="aghuse.saude.ba.gov.br"
          class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
        />
      </label>
      <div class="hidden lg:flex items-end justify-center pb-2 text-slate-500">
        →
      </div>
      <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
        IP fixo
        <input
          v-model="form.address"
          type="text"
          placeholder="10.0.0.1"
          class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
        />
      </label>
      <div class="flex items-end">
        <button
          type="button"
          class="w-full rounded-lg border border-sky-400/40 bg-sky-500/10 px-4 py-2 text-sm font-semibold text-sky-100 transition hover:bg-sky-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          :disabled="saveBusy || !form.host.trim() || !form.address.trim()"
          @click="saveOverride"
        >
          {{ saveBusy ? "Salvando..." : "Salvar override" }}
        </button>
      </div>
    </div>

    <div v-if="saveMessage" class="mt-3 text-sm text-emerald-300">
      {{ saveMessage }}
    </div>
    <div v-if="saveError" class="mt-3 text-sm text-rose-300">
      {{ saveError }}
    </div>

    <div v-if="hasOverrides" class="mt-4 overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50">
      <table class="min-w-full divide-y divide-slate-800 text-sm">
        <thead class="text-slate-400">
          <tr>
            <th class="px-4 py-3 text-left font-medium">Hostname</th>
            <th class="px-4 py-3 text-left font-medium">IP</th>
            <th class="px-4 py-3 text-left font-medium">Atualizado</th>
            <th class="px-4 py-3 text-left font-medium"></th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-800">
          <tr v-for="entry in overrides" :key="entry.host" class="hover:bg-slate-900/70">
            <td class="px-4 py-3 font-mono text-slate-200">
              {{ entry.host }}
            </td>
            <td class="px-4 py-3 font-mono text-sky-200">
              {{ entry.address }}
            </td>
            <td class="px-4 py-3 text-slate-400">
              <template v-if="entry.updatedAt">
                {{ formatRelative(entry.updatedAt) }}
                <span class="text-slate-500">({{ formatAbsolute(entry.updatedAt) }})</span>
              </template>
              <template v-else>
                -
              </template>
            </td>
            <td class="px-4 py-3 text-right">
              <button
                type="button"
                class="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-rose-200 transition hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                :disabled="deletingHost === entry.host"
                @click="deleteOverride(entry.host)"
              >
                {{ deletingHost === entry.host ? "Removendo..." : "Remover" }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div
      v-else
      class="mt-4 rounded-xl border border-dashed border-slate-800 bg-slate-900/40 p-6 text-center text-sm text-slate-400"
    >
      Nenhum override configurado.
    </div>
  </section>
</template>
