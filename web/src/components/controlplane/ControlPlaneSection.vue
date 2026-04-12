<script setup lang="ts">
import { computed, reactive, ref, watch } from "vue";

import type {
  StatusAgentGroup,
  StatusDestinationProfile,
} from "../../types/status";
import { formatAbsolute, formatRelative } from "../../utils/format";

const props = defineProps<{
  agentGroups: StatusAgentGroup[];
  destinationProfiles: StatusDestinationProfile[];
}>();

const emit = defineEmits<{
  (e: "refreshRequested"): void;
}>();

const groupForm = reactive({
  id: "",
  name: "",
  slug: "",
  description: "",
  routingMode: "health-first",
});
const profileForm = reactive({
  id: "",
  name: "",
  slug: "",
  host: "",
  port: "443",
  protocolHint: "https",
  defaultGroupId: "",
  notes: "",
});

const groupBusy = ref(false);
const groupError = ref("");
const groupMessage = ref("");
const deletingGroupId = ref("");

const profileBusy = ref(false);
const profileError = ref("");
const profileMessage = ref("");
const deletingProfileId = ref("");

const hasGroups = computed(() => props.agentGroups.length > 0);
const hasProfiles = computed(() => props.destinationProfiles.length > 0);

watch(
  () => props.agentGroups,
  (groups) => {
    if (!profileForm.id && !profileForm.defaultGroupId && groups.length > 0) {
      profileForm.defaultGroupId = groups[0].id;
    }
  },
  { deep: true, immediate: true },
);

function normalizeSlug(input: string) {
  return input
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

async function readError(res: Response) {
  const message = (await res.text()).trim();
  return message || `HTTP ${res.status}`;
}

function resetGroupForm() {
  groupForm.id = "";
  groupForm.name = "";
  groupForm.slug = "";
  groupForm.description = "";
  groupForm.routingMode = "health-first";
}

function resetProfileForm() {
  profileForm.id = "";
  profileForm.name = "";
  profileForm.slug = "";
  profileForm.host = "";
  profileForm.port = "443";
  profileForm.protocolHint = "https";
  profileForm.defaultGroupId = props.agentGroups[0]?.id ?? "";
  profileForm.notes = "";
}

function editGroup(group: StatusAgentGroup) {
  groupForm.id = group.id;
  groupForm.name = group.name;
  groupForm.slug = group.slug;
  groupForm.description = group.description ?? "";
  groupForm.routingMode = group.routingMode ?? "health-first";
  groupError.value = "";
  groupMessage.value = "";
}

function editProfile(profile: StatusDestinationProfile) {
  profileForm.id = profile.id;
  profileForm.name = profile.name;
  profileForm.slug = profile.slug;
  profileForm.host = profile.host;
  profileForm.port = String(profile.port);
  profileForm.protocolHint = profile.protocolHint ?? "https";
  profileForm.defaultGroupId = profile.defaultGroupId ?? "";
  profileForm.notes = profile.notes ?? "";
  profileError.value = "";
  profileMessage.value = "";
}

async function saveGroup() {
  groupBusy.value = true;
  groupError.value = "";
  groupMessage.value = "";
  try {
    const editing = groupForm.id.trim() !== "";
    const res = await fetch(
      editing
        ? `/api/control-plane/agent-groups/${encodeURIComponent(groupForm.id)}`
        : "/api/control-plane/agent-groups",
      {
        method: editing ? "PUT" : "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          name: groupForm.name.trim(),
          slug: normalizeSlug(groupForm.slug || groupForm.name),
          description: groupForm.description.trim(),
          routingMode: groupForm.routingMode.trim() || "health-first",
        }),
      },
    );
    if (!res.ok) {
      throw new Error(await readError(res));
    }
    groupMessage.value = editing
      ? "Grupo atualizado."
      : "Grupo criado e persistido no relay.";
    resetGroupForm();
    emit("refreshRequested");
  } catch (err) {
    groupError.value =
      err instanceof Error ? err.message : "Falha ao salvar grupo.";
  } finally {
    groupBusy.value = false;
  }
}

async function deleteGroup(group: StatusAgentGroup) {
  deletingGroupId.value = group.id;
  groupError.value = "";
  groupMessage.value = "";
  try {
    const res = await fetch(
      `/api/control-plane/agent-groups/${encodeURIComponent(group.id)}`,
      {
        method: "DELETE",
      },
    );
    if (!res.ok) {
      throw new Error(await readError(res));
    }
    if (groupForm.id === group.id) {
      resetGroupForm();
    }
    groupMessage.value = `Grupo ${group.name} removido.`;
    emit("refreshRequested");
  } catch (err) {
    groupError.value =
      err instanceof Error ? err.message : "Falha ao remover grupo.";
  } finally {
    deletingGroupId.value = "";
  }
}

async function saveProfile() {
  profileBusy.value = true;
  profileError.value = "";
  profileMessage.value = "";
  try {
    const editing = profileForm.id.trim() !== "";
    const res = await fetch(
      editing
        ? `/api/control-plane/destination-profiles/${encodeURIComponent(profileForm.id)}`
        : "/api/control-plane/destination-profiles",
      {
        method: editing ? "PUT" : "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          name: profileForm.name.trim(),
          slug: normalizeSlug(profileForm.slug || profileForm.name),
          host: profileForm.host.trim(),
          port: Number(profileForm.port),
          protocolHint: profileForm.protocolHint.trim() || "tcp",
          defaultGroupId: profileForm.defaultGroupId,
          notes: profileForm.notes.trim(),
        }),
      },
    );
    if (!res.ok) {
      throw new Error(await readError(res));
    }
    profileMessage.value = editing
      ? "Perfil atualizado."
      : "Perfil criado e pronto para roteamento.";
    resetProfileForm();
    emit("refreshRequested");
  } catch (err) {
    profileError.value =
      err instanceof Error ? err.message : "Falha ao salvar perfil.";
  } finally {
    profileBusy.value = false;
  }
}

async function deleteProfile(profile: StatusDestinationProfile) {
  deletingProfileId.value = profile.id;
  profileError.value = "";
  profileMessage.value = "";
  try {
    const res = await fetch(
      `/api/control-plane/destination-profiles/${encodeURIComponent(profile.id)}`,
      {
        method: "DELETE",
      },
    );
    if (!res.ok) {
      throw new Error(await readError(res));
    }
    if (profileForm.id === profile.id) {
      resetProfileForm();
    }
    profileMessage.value = `Perfil ${profile.name} removido.`;
    emit("refreshRequested");
  } catch (err) {
    profileError.value =
      err instanceof Error ? err.message : "Falha ao remover perfil.";
  } finally {
    deletingProfileId.value = "";
  }
}
</script>

<template>
  <section class="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
    <div class="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h2 class="text-xl font-semibold">Control Plane</h2>
        <p class="mt-1 text-sm text-slate-400">
          Gerencie grupos lógicos de agentes e perfis de destino persistidos no
          SQLite do relay.
        </p>
      </div>
      <div class="text-sm text-slate-500">
        {{ agentGroups.length }} grupos · {{ destinationProfiles.length }} perfis
      </div>
    </div>

    <div class="grid gap-6 xl:grid-cols-2">
      <section class="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
        <div class="mb-4 flex items-center justify-between">
          <div>
            <h3 class="text-lg font-semibold text-slate-100">Grupos de agentes</h3>
            <p class="mt-1 text-sm text-slate-400">
              Pools lógicos usados pelo relay para selecionar o melhor agente.
            </p>
          </div>
          <button
            v-if="groupForm.id"
            type="button"
            class="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
            @click="resetGroupForm"
          >
            Cancelar edição
          </button>
        </div>

        <div class="grid gap-3 md:grid-cols-2">
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Nome
            <input
              v-model="groupForm.name"
              type="text"
              placeholder="Hospital Salvador"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            />
          </label>
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Slug
            <input
              v-model="groupForm.slug"
              type="text"
              placeholder="hospital-salvador"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            />
          </label>
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Routing mode
            <select
              v-model="groupForm.routingMode"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            >
              <option value="health-first">health-first</option>
              <option value="latency-first">latency-first</option>
              <option value="priority-first">priority-first</option>
            </select>
          </label>
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300 md:col-span-2">
            Descrição
            <textarea
              v-model="groupForm.description"
              rows="3"
              placeholder="Rede hospitalar de Salvador"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            />
          </label>
        </div>

        <div class="mt-4 flex items-center gap-3">
          <button
            type="button"
            class="rounded-lg border border-sky-400/40 bg-sky-500/10 px-4 py-2 text-sm font-semibold text-sky-100 transition hover:bg-sky-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="groupBusy || !groupForm.name.trim()"
            @click="saveGroup"
          >
            {{ groupBusy ? "Salvando..." : groupForm.id ? "Atualizar grupo" : "Criar grupo" }}
          </button>
          <span class="text-xs text-slate-500">
            Se o slug estiver vazio, ele será gerado a partir do nome.
          </span>
        </div>

        <div v-if="groupMessage" class="mt-3 text-sm text-emerald-300">
          {{ groupMessage }}
        </div>
        <div v-if="groupError" class="mt-3 text-sm text-rose-300">
          {{ groupError }}
        </div>

        <div
          v-if="hasGroups"
          class="mt-4 overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50"
        >
          <table class="min-w-full divide-y divide-slate-800 text-sm">
            <thead class="text-slate-400">
              <tr>
                <th class="px-4 py-3 text-left font-medium">Grupo</th>
                <th class="px-4 py-3 text-left font-medium">Modo</th>
                <th class="px-4 py-3 text-left font-medium">Agentes</th>
                <th class="px-4 py-3 text-left font-medium">Atualizado</th>
                <th class="px-4 py-3 text-right font-medium"></th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800">
              <tr
                v-for="group in agentGroups"
                :key="group.id"
                class="hover:bg-slate-900/70"
              >
                <td class="px-4 py-3">
                  <div class="flex items-center gap-2">
                    <span class="font-semibold text-slate-100">{{ group.name }}</span>
                    <span
                      v-if="group.legacy"
                      class="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-amber-200"
                    >
                      legado
                    </span>
                  </div>
                  <div class="mt-1 font-mono text-xs text-slate-400">
                    {{ group.slug }}
                  </div>
                  <div
                    v-if="group.description"
                    class="mt-1 text-xs text-slate-500"
                  >
                    {{ group.description }}
                  </div>
                </td>
                <td class="px-4 py-3 font-mono text-slate-300">
                  {{ group.routingMode || "health-first" }}
                </td>
                <td class="px-4 py-3 text-slate-300">
                  {{ group.enabledMemberCount ?? 0 }}/{{ group.memberCount ?? 0 }}
                </td>
                <td class="px-4 py-3 text-slate-400">
                  <template v-if="group.updatedAt">
                    {{ formatRelative(group.updatedAt) }}
                    <span class="text-slate-500">
                      ({{ formatAbsolute(group.updatedAt) }})
                    </span>
                  </template>
                  <template v-else>
                    -
                  </template>
                </td>
                <td class="px-4 py-3">
                  <div class="flex justify-end gap-2">
                    <button
                      type="button"
                      class="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-200 transition hover:border-sky-400 hover:text-sky-100 disabled:cursor-not-allowed disabled:opacity-50"
                      :disabled="group.legacy"
                      @click="editGroup(group)"
                    >
                      Editar
                    </button>
                    <button
                      type="button"
                      class="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-rose-200 transition hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                      :disabled="group.legacy || deletingGroupId === group.id"
                      @click="deleteGroup(group)"
                    >
                      {{ deletingGroupId === group.id ? "Removendo..." : "Remover" }}
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
        <div class="mb-4 flex items-center justify-between">
          <div>
            <h3 class="text-lg font-semibold text-slate-100">Perfis de destino</h3>
            <p class="mt-1 text-sm text-slate-400">
              Destinos nomeados que apontam para aplicações internas comuns.
            </p>
          </div>
          <button
            v-if="profileForm.id"
            type="button"
            class="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
            @click="resetProfileForm"
          >
            Cancelar edição
          </button>
        </div>

        <div class="grid gap-3 md:grid-cols-2">
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Nome
            <input
              v-model="profileForm.name"
              type="text"
              placeholder="AGHUse"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            />
          </label>
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Slug
            <input
              v-model="profileForm.slug"
              type="text"
              placeholder="aghuse"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            />
          </label>
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Hostname
            <input
              v-model="profileForm.host"
              type="text"
              placeholder="aghuse.saude.ba.gov.br"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            />
          </label>
          <div class="grid gap-3 sm:grid-cols-[minmax(0,1fr)_120px]">
            <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
              Grupo padrão
              <select
                v-model="profileForm.defaultGroupId"
                class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
              >
                <option value="" disabled>Selecione um grupo</option>
                <option
                  v-for="group in agentGroups"
                  :key="group.id"
                  :value="group.id"
                >
                  {{ group.name }}
                </option>
              </select>
            </label>
            <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
              Porta
              <input
                v-model="profileForm.port"
                type="number"
                min="1"
                max="65535"
                class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
              />
            </label>
          </div>
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Protocolo
            <input
              v-model="profileForm.protocolHint"
              type="text"
              placeholder="https"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            />
          </label>
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300 md:col-span-2">
            Observações
            <textarea
              v-model="profileForm.notes"
              rows="3"
              placeholder="Aplicação hospitalar interna"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            />
          </label>
        </div>

        <div class="mt-4 flex items-center gap-3">
          <button
            type="button"
            class="rounded-lg border border-emerald-400/40 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-100 transition hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="profileBusy || !profileForm.name.trim() || !profileForm.host.trim() || !profileForm.defaultGroupId"
            @click="saveProfile"
          >
            {{ profileBusy ? "Salvando..." : profileForm.id ? "Atualizar perfil" : "Criar perfil" }}
          </button>
          <span class="text-xs text-slate-500">
            O grupo padrão define o pool inicial usado pelo roteamento.
          </span>
        </div>

        <div v-if="profileMessage" class="mt-3 text-sm text-emerald-300">
          {{ profileMessage }}
        </div>
        <div v-if="profileError" class="mt-3 text-sm text-rose-300">
          {{ profileError }}
        </div>

        <div
          v-if="hasProfiles"
          class="mt-4 overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50"
        >
          <table class="min-w-full divide-y divide-slate-800 text-sm">
            <thead class="text-slate-400">
              <tr>
                <th class="px-4 py-3 text-left font-medium">Perfil</th>
                <th class="px-4 py-3 text-left font-medium">Destino</th>
                <th class="px-4 py-3 text-left font-medium">Grupo</th>
                <th class="px-4 py-3 text-left font-medium">Atualizado</th>
                <th class="px-4 py-3 text-right font-medium"></th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800">
              <tr
                v-for="profile in destinationProfiles"
                :key="profile.id"
                class="hover:bg-slate-900/70"
              >
                <td class="px-4 py-3">
                  <div class="font-semibold text-slate-100">{{ profile.name }}</div>
                  <div class="mt-1 font-mono text-xs text-slate-400">
                    {{ profile.slug }}
                  </div>
                  <div
                    v-if="profile.notes"
                    class="mt-1 text-xs text-slate-500"
                  >
                    {{ profile.notes }}
                  </div>
                </td>
                <td class="px-4 py-3">
                  <div class="font-mono text-sky-200">
                    {{ profile.host }}:{{ profile.port }}
                  </div>
                  <div class="mt-1 text-xs text-slate-500">
                    {{ profile.protocolHint || "tcp" }}
                  </div>
                </td>
                <td class="px-4 py-3 text-slate-300">
                  {{ profile.defaultGroupName || profile.defaultGroupId || "-" }}
                </td>
                <td class="px-4 py-3 text-slate-400">
                  <template v-if="profile.updatedAt">
                    {{ formatRelative(profile.updatedAt) }}
                    <span class="text-slate-500">
                      ({{ formatAbsolute(profile.updatedAt) }})
                    </span>
                  </template>
                  <template v-else>
                    -
                  </template>
                </td>
                <td class="px-4 py-3">
                  <div class="flex justify-end gap-2">
                    <button
                      type="button"
                      class="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-200 transition hover:border-emerald-400 hover:text-emerald-100"
                      @click="editProfile(profile)"
                    >
                      Editar
                    </button>
                    <button
                      type="button"
                      class="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-rose-200 transition hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                      :disabled="deletingProfileId === profile.id"
                      @click="deleteProfile(profile)"
                    >
                      {{ deletingProfileId === profile.id ? "Removendo..." : "Remover" }}
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div
          v-else
          class="mt-4 rounded-xl border border-dashed border-slate-800 bg-slate-900/40 p-6 text-center text-sm text-slate-400"
        >
          Nenhum perfil de destino cadastrado.
        </div>
      </section>
    </div>
  </section>
</template>
