<script setup lang="ts">
import { ref } from "vue";

import AccessControlSection from "../controlplane/AccessControlSection.vue";
import ControlPlaneSection from "../controlplane/ControlPlaneSection.vue";
import DNSOverridesSection from "../dns/DNSOverridesSection.vue";
import type {
  StatusAgent,
  StatusAgentGroup,
  StatusDestinationProfile,
  StatusDNSOverride,
} from "../../types/status";

type ConfigTab = "groups" | "access" | "dns";

defineProps<{
  agentGroups: StatusAgentGroup[];
  destinationProfiles: StatusDestinationProfile[];
  agents: StatusAgent[];
  dnsOverrides: StatusDNSOverride[];
}>();

const emit = defineEmits<{
  (e: "refreshRequested"): void;
}>();

const activeConfigTab = ref<ConfigTab>("groups");

function tabClass(tab: ConfigTab): string {
  const base =
    "whitespace-nowrap px-4 py-2.5 text-sm font-medium border-b-2 transition -mb-px";
  if (activeConfigTab.value === tab) {
    return `${base} border-sky-400 text-sky-100`;
  }
  return `${base} border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-600`;
}
</script>

<template>
  <section class="space-y-4">
    <!-- Sub-tabs -->
    <div class="border-b border-slate-800">
      <nav class="flex gap-0 overflow-x-auto">
        <button type="button" :class="tabClass('groups')" @click="activeConfigTab = 'groups'">
          Grupos & Perfis
        </button>
        <button type="button" :class="tabClass('access')" @click="activeConfigTab = 'access'">
          Controle de Acesso
        </button>
        <button type="button" :class="tabClass('dns')" @click="activeConfigTab = 'dns'">
          DNS Overrides
        </button>
      </nav>
    </div>

    <!-- Conteúdo -->
    <ControlPlaneSection
      v-if="activeConfigTab === 'groups'"
      :agent-groups="agentGroups"
      :destination-profiles="destinationProfiles"
      @refresh-requested="emit('refreshRequested')"
    />
    <AccessControlSection
      v-if="activeConfigTab === 'access'"
      :agent-groups="agentGroups"
      :destination-profiles="destinationProfiles"
      :agents="agents"
      @refresh-requested="emit('refreshRequested')"
    />
    <DNSOverridesSection
      v-if="activeConfigTab === 'dns'"
      :overrides="dnsOverrides"
      @refresh-requested="emit('refreshRequested')"
    />
  </section>
</template>
