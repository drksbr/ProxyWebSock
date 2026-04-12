<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from "vue";

import type {
  StatusAgent,
  StatusAgentGroup,
  StatusDestinationProfile,
} from "../../types/status";
import { formatRelative } from "../../utils/format";

type ControlPlaneUser = {
  id: string;
  username: string;
  status: string;
  role: string;
  createdAt?: string;
  updatedAt?: string;
};

type ControlPlaneMembership = {
  groupId: string;
  groupName?: string;
  agentId: string;
  agentIdentification?: string;
  agentLocation?: string;
  priority: number;
  weight: number;
  enabled: boolean;
  connected?: boolean;
  createdAt?: string;
  updatedAt?: string;
};

type ControlPlaneAccessGrant = {
  id: string;
  userId: string;
  username?: string;
  groupId?: string;
  groupName?: string;
  destinationProfileId?: string;
  destinationProfileName?: string;
  accessMode?: string;
  createdAt?: string;
  updatedAt?: string;
};

type UserAutoConfigResponse = {
  userId: string;
  username: string;
  pacUrl: string;
  catchAll: boolean;
  profileHosts?: string[];
  proxyListen?: string;
  socksListen?: string;
  requiresProxyAuth?: boolean;
};

const props = defineProps<{
  agentGroups: StatusAgentGroup[];
  destinationProfiles: StatusDestinationProfile[];
  agents: StatusAgent[];
}>();

const emit = defineEmits<{
  (e: "refreshRequested"): void;
}>();

const users = ref<ControlPlaneUser[]>([]);
const memberships = ref<ControlPlaneMembership[]>([]);
const grants = ref<ControlPlaneAccessGrant[]>([]);
const loading = ref(false);
const loadError = ref("");

const userForm = reactive({
  id: "",
  username: "",
  password: "",
  status: "active",
  role: "user",
});
const membershipForm = reactive({
  groupId: "",
  agentId: "",
  priority: "0",
  weight: "1",
  enabled: true,
});
const grantForm = reactive({
  id: "",
  userId: "",
  groupId: "",
  destinationProfileId: "",
  accessMode: "direct",
});

const userBusy = ref(false);
const userError = ref("");
const userMessage = ref("");
const deletingUserId = ref("");

const membershipBusy = ref(false);
const membershipError = ref("");
const membershipMessage = ref("");
const deletingMembershipKey = ref("");

const grantBusy = ref(false);
const grantError = ref("");
const grantMessage = ref("");
const deletingGrantId = ref("");
const pacBusyUserId = ref("");
const pacError = ref("");
const pacInfo = ref<UserAutoConfigResponse | null>(null);

const hasUsers = computed(() => users.value.length > 0);
const hasMemberships = computed(() => memberships.value.length > 0);
const hasGrants = computed(() => grants.value.length > 0);

watch(
  () => props.agentGroups,
  (groups) => {
    if (!membershipForm.groupId && groups.length > 0) {
      membershipForm.groupId = groups[0].id;
    }
    if (!grantForm.groupId && !grantForm.destinationProfileId && groups.length > 0) {
      grantForm.groupId = groups[0].id;
    }
  },
  { deep: true, immediate: true },
);

watch(
  users,
  (items) => {
    if (!grantForm.userId && items.length > 0) {
      grantForm.userId = items[0].id;
    }
  },
  { deep: true, immediate: true },
);

watch(
  () => props.agents,
  (agents) => {
    if (!membershipForm.agentId && agents.length > 0) {
      membershipForm.agentId = agents[0].id;
    }
  },
  { deep: true, immediate: true },
);

onMounted(() => {
  void refreshData();
});

async function readError(res: Response) {
  const text = (await res.text()).trim();
  return text || `HTTP ${res.status}`;
}

async function refreshData() {
  loading.value = true;
  loadError.value = "";
  try {
    const [usersRes, membershipsRes, grantsRes] = await Promise.all([
      fetch("/api/control-plane/users", { cache: "no-store" }),
      fetch("/api/control-plane/agent-memberships", { cache: "no-store" }),
      fetch("/api/control-plane/access-grants", { cache: "no-store" }),
    ]);
    if (!usersRes.ok) {
      throw new Error(await readError(usersRes));
    }
    if (!membershipsRes.ok) {
      throw new Error(await readError(membershipsRes));
    }
    if (!grantsRes.ok) {
      throw new Error(await readError(grantsRes));
    }
    const usersPayload = (await usersRes.json()) as { users?: ControlPlaneUser[] };
    const membershipsPayload = (await membershipsRes.json()) as {
      memberships?: ControlPlaneMembership[];
    };
    const grantsPayload = (await grantsRes.json()) as {
      grants?: ControlPlaneAccessGrant[];
    };
    users.value = usersPayload.users ?? [];
    memberships.value = membershipsPayload.memberships ?? [];
    grants.value = grantsPayload.grants ?? [];
  } catch (err) {
    loadError.value =
      err instanceof Error ? err.message : "Falha ao carregar controle de acesso.";
  } finally {
    loading.value = false;
  }
}

function resetUserForm() {
  userForm.id = "";
  userForm.username = "";
  userForm.password = "";
  userForm.status = "active";
  userForm.role = "user";
}

function resetMembershipForm() {
  membershipForm.groupId = props.agentGroups[0]?.id ?? "";
  membershipForm.agentId = props.agents[0]?.id ?? "";
  membershipForm.priority = "0";
  membershipForm.weight = "1";
  membershipForm.enabled = true;
}

function resetGrantForm() {
  grantForm.id = "";
  grantForm.userId = users.value[0]?.id ?? "";
  grantForm.groupId = props.agentGroups[0]?.id ?? "";
  grantForm.destinationProfileId = "";
  grantForm.accessMode = "direct";
}

function editUser(user: ControlPlaneUser) {
  userForm.id = user.id;
  userForm.username = user.username;
  userForm.password = "";
  userForm.status = user.status || "active";
  userForm.role = user.role || "user";
  userError.value = "";
  userMessage.value = "";
}

async function loadUserPAC(user: ControlPlaneUser) {
  pacBusyUserId.value = user.id;
  pacError.value = "";
  try {
    const res = await fetch(
      `/api/control-plane/users/${encodeURIComponent(user.id)}/autoconfig`,
      {
        cache: "no-store",
      },
    );
    if (!res.ok) {
      throw new Error(await readError(res));
    }
    pacInfo.value = (await res.json()) as UserAutoConfigResponse;
  } catch (err) {
    pacError.value =
      err instanceof Error ? err.message : "Falha ao gerar autoconfig.";
  } finally {
    pacBusyUserId.value = "";
  }
}

function editMembership(membership: ControlPlaneMembership) {
  membershipForm.groupId = membership.groupId;
  membershipForm.agentId = membership.agentId;
  membershipForm.priority = String(membership.priority ?? 0);
  membershipForm.weight = String(membership.weight ?? 1);
  membershipForm.enabled = membership.enabled;
  membershipError.value = "";
  membershipMessage.value = "";
}

function editGrant(grant: ControlPlaneAccessGrant) {
  grantForm.id = grant.id;
  grantForm.userId = grant.userId;
  grantForm.groupId = grant.groupId ?? "";
  grantForm.destinationProfileId = grant.destinationProfileId ?? "";
  grantForm.accessMode = grant.accessMode ?? "direct";
  grantError.value = "";
  grantMessage.value = "";
}

function membershipKey(groupId: string, agentId: string) {
  return `${groupId}:${agentId}`;
}

function isAgentConnected(agentId: string) {
  return props.agents.some(
    (agent) => agent.id === agentId && agent.status !== "disconnected",
  );
}

async function saveUser() {
  userBusy.value = true;
  userError.value = "";
  userMessage.value = "";
  try {
    const editing = userForm.id.trim() !== "";
    const res = await fetch(
      editing
        ? `/api/control-plane/users/${encodeURIComponent(userForm.id)}`
        : "/api/control-plane/users",
      {
        method: editing ? "PUT" : "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: userForm.username.trim(),
          password: userForm.password,
          status: userForm.status,
          role: userForm.role,
        }),
      },
    );
    if (!res.ok) {
      throw new Error(await readError(res));
    }
    userMessage.value = editing ? "Usuário atualizado." : "Usuário criado.";
    resetUserForm();
    await refreshData();
    emit("refreshRequested");
  } catch (err) {
    userError.value =
      err instanceof Error ? err.message : "Falha ao salvar usuário.";
  } finally {
    userBusy.value = false;
  }
}

async function deleteUser(user: ControlPlaneUser) {
  deletingUserId.value = user.id;
  userError.value = "";
  userMessage.value = "";
  try {
    const res = await fetch(`/api/control-plane/users/${encodeURIComponent(user.id)}`, {
      method: "DELETE",
    });
    if (!res.ok) {
      throw new Error(await readError(res));
    }
    if (userForm.id === user.id) {
      resetUserForm();
    }
    userMessage.value = `Usuário ${user.username} removido.`;
    await refreshData();
    emit("refreshRequested");
  } catch (err) {
    userError.value =
      err instanceof Error ? err.message : "Falha ao remover usuário.";
  } finally {
    deletingUserId.value = "";
  }
}

async function saveMembership() {
  membershipBusy.value = true;
  membershipError.value = "";
  membershipMessage.value = "";
  try {
    const groupId = membershipForm.groupId;
    const agentId = membershipForm.agentId;
    const editing = memberships.value.some(
      (membership) =>
        membership.groupId === groupId && membership.agentId === agentId,
    );
    const res = await fetch(
      editing
        ? `/api/control-plane/agent-memberships/${encodeURIComponent(groupId)}/${encodeURIComponent(agentId)}`
        : "/api/control-plane/agent-memberships",
      {
        method: editing ? "PUT" : "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          groupId,
          agentId,
          priority: Number(membershipForm.priority),
          weight: Number(membershipForm.weight),
          enabled: membershipForm.enabled,
        }),
      },
    );
    if (!res.ok) {
      throw new Error(await readError(res));
    }
    membershipMessage.value = editing
      ? "Membership atualizada."
      : "Membership criada.";
    resetMembershipForm();
    await refreshData();
    emit("refreshRequested");
  } catch (err) {
    membershipError.value =
      err instanceof Error ? err.message : "Falha ao salvar membership.";
  } finally {
    membershipBusy.value = false;
  }
}

async function deleteMembership(membership: ControlPlaneMembership) {
  const key = membershipKey(membership.groupId, membership.agentId);
  deletingMembershipKey.value = key;
  membershipError.value = "";
  membershipMessage.value = "";
  try {
    const res = await fetch(
      `/api/control-plane/agent-memberships/${encodeURIComponent(membership.groupId)}/${encodeURIComponent(membership.agentId)}`,
      {
        method: "DELETE",
      },
    );
    if (!res.ok) {
      throw new Error(await readError(res));
    }
    if (membershipForm.groupId === membership.groupId && membershipForm.agentId === membership.agentId) {
      resetMembershipForm();
    }
    membershipMessage.value = `Membership ${membership.groupName} / ${membership.agentId} removida.`;
    await refreshData();
    emit("refreshRequested");
  } catch (err) {
    membershipError.value =
      err instanceof Error ? err.message : "Falha ao remover membership.";
  } finally {
    deletingMembershipKey.value = "";
  }
}

async function saveGrant() {
  grantBusy.value = true;
  grantError.value = "";
  grantMessage.value = "";
  try {
    const editing = grantForm.id.trim() !== "";
    const res = await fetch(
      editing
        ? `/api/control-plane/access-grants/${encodeURIComponent(grantForm.id)}`
        : "/api/control-plane/access-grants",
      {
        method: editing ? "PUT" : "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          userId: grantForm.userId,
          groupId: grantForm.groupId,
          destinationProfileId: grantForm.destinationProfileId,
          accessMode: grantForm.accessMode,
        }),
      },
    );
    if (!res.ok) {
      throw new Error(await readError(res));
    }
    grantMessage.value = editing ? "Grant atualizado." : "Grant criado.";
    resetGrantForm();
    await refreshData();
    emit("refreshRequested");
  } catch (err) {
    grantError.value =
      err instanceof Error ? err.message : "Falha ao salvar grant.";
  } finally {
    grantBusy.value = false;
  }
}

async function deleteGrant(grant: ControlPlaneAccessGrant) {
  deletingGrantId.value = grant.id;
  grantError.value = "";
  grantMessage.value = "";
  try {
    const res = await fetch(
      `/api/control-plane/access-grants/${encodeURIComponent(grant.id)}`,
      {
        method: "DELETE",
      },
    );
    if (!res.ok) {
      throw new Error(await readError(res));
    }
    if (grantForm.id === grant.id) {
      resetGrantForm();
    }
    grantMessage.value = `Grant de ${grant.username || grant.userId} removido.`;
    await refreshData();
    emit("refreshRequested");
  } catch (err) {
    grantError.value =
      err instanceof Error ? err.message : "Falha ao remover grant.";
  } finally {
    deletingGrantId.value = "";
  }
}
</script>

<template>
  <section class="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
    <div class="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h2 class="text-xl font-semibold">Acesso e Grants</h2>
        <p class="mt-1 text-sm text-slate-400">
          Usuários finais, vínculo de agentes aos grupos e grants usados pelo
          roteamento automático do relay.
        </p>
      </div>
      <button
        type="button"
        class="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-300 transition hover:border-slate-500 hover:text-slate-100 disabled:opacity-50"
        :disabled="loading"
        @click="refreshData"
      >
        {{ loading ? "Atualizando..." : "Recarregar" }}
      </button>
    </div>

    <div v-if="loadError" class="mb-4 text-sm text-rose-300">
      {{ loadError }}
    </div>

    <div class="grid gap-6 xl:grid-cols-3">
      <section class="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
        <div class="mb-4 flex items-center justify-between">
          <div>
            <h3 class="text-lg font-semibold text-slate-100">Usuários</h3>
            <p class="mt-1 text-sm text-slate-400">
              Credenciais que autenticam no relay, sem expor token de agente.
            </p>
          </div>
          <button
            v-if="userForm.id"
            type="button"
            class="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
            @click="resetUserForm"
          >
            Cancelar
          </button>
        </div>

        <div class="grid gap-3">
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Username
            <input
              v-model="userForm.username"
              type="text"
              placeholder="operador"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            />
          </label>
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Senha
            <input
              v-model="userForm.password"
              type="password"
              :placeholder="userForm.id ? 'Deixe em branco para manter' : 'Senha inicial'"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            />
          </label>
          <div class="grid gap-3 sm:grid-cols-2">
            <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
              Status
              <select
                v-model="userForm.status"
                class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
              >
                <option value="active">active</option>
                <option value="disabled">disabled</option>
              </select>
            </label>
            <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
              Papel
              <select
                v-model="userForm.role"
                class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
              >
                <option value="user">user</option>
                <option value="operator">operator</option>
                <option value="admin">admin</option>
              </select>
            </label>
          </div>
        </div>

        <div class="mt-4 flex items-center gap-3">
          <button
            type="button"
            class="rounded-lg border border-sky-400/40 bg-sky-500/10 px-4 py-2 text-sm font-semibold text-sky-100 transition hover:bg-sky-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="userBusy || !userForm.username.trim() || (!userForm.id && !userForm.password)"
            @click="saveUser"
          >
            {{ userBusy ? "Salvando..." : userForm.id ? "Atualizar usuário" : "Criar usuário" }}
          </button>
        </div>

        <div v-if="userMessage" class="mt-3 text-sm text-emerald-300">
          {{ userMessage }}
        </div>
        <div v-if="userError" class="mt-3 text-sm text-rose-300">
          {{ userError }}
        </div>

        <div
          v-if="hasUsers"
          class="mt-4 overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50"
        >
          <table class="min-w-full divide-y divide-slate-800 text-sm">
            <thead class="text-slate-400">
              <tr>
                <th class="px-4 py-3 text-left font-medium">Username</th>
                <th class="px-4 py-3 text-left font-medium">Role</th>
                <th class="px-4 py-3 text-left font-medium">Status</th>
                <th class="px-4 py-3 text-right font-medium"></th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800">
              <tr v-for="user in users" :key="user.id" class="hover:bg-slate-900/70">
                <td class="px-4 py-3">
                  <div class="font-semibold text-slate-100">{{ user.username }}</div>
                  <div v-if="user.updatedAt" class="mt-1 text-xs text-slate-500">
                    {{ formatRelative(user.updatedAt) }}
                  </div>
                </td>
                <td class="px-4 py-3 font-mono text-slate-300">{{ user.role }}</td>
                <td class="px-4 py-3">
                  <span
                    class="rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide"
                    :class="
                      user.status === 'active'
                        ? 'border border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
                        : 'border border-rose-500/30 bg-rose-500/10 text-rose-200'
                    "
                  >
                    {{ user.status }}
                  </span>
                </td>
                <td class="px-4 py-3">
                  <div class="flex justify-end gap-2">
                    <button
                      type="button"
                      class="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-200 transition hover:border-sky-400 hover:text-sky-100"
                      @click="editUser(user)"
                    >
                      Editar
                    </button>
                    <button
                      type="button"
                      class="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-emerald-200 transition hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                      :disabled="pacBusyUserId === user.id"
                      @click="loadUserPAC(user)"
                    >
                      {{ pacBusyUserId === user.id ? "Gerando..." : "PAC" }}
                    </button>
                    <button
                      type="button"
                      class="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-rose-200 transition hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                      :disabled="deletingUserId === user.id"
                      @click="deleteUser(user)"
                    >
                      {{ deletingUserId === user.id ? "Removendo..." : "Remover" }}
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
            <h3 class="text-lg font-semibold text-slate-100">Memberships</h3>
            <p class="mt-1 text-sm text-slate-400">
              Define quais agentes participam de cada grupo lógico.
            </p>
          </div>
          <button
            type="button"
            class="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
            @click="resetMembershipForm"
          >
            Limpar
          </button>
        </div>

        <div class="grid gap-3">
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Grupo
            <select
              v-model="membershipForm.groupId"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            >
              <option value="" disabled>Selecione</option>
              <option v-for="group in agentGroups" :key="group.id" :value="group.id">
                {{ group.name }}
              </option>
            </select>
          </label>
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Agente
            <select
              v-model="membershipForm.agentId"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            >
              <option value="" disabled>Selecione</option>
              <option v-for="agent in agents" :key="agent.id" :value="agent.id">
                {{ agent.identification || agent.id }} ({{ agent.id }})
              </option>
            </select>
          </label>
          <div class="grid gap-3 sm:grid-cols-2">
            <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
              Priority
              <input
                v-model="membershipForm.priority"
                type="number"
                class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
              />
            </label>
            <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
              Weight
              <input
                v-model="membershipForm.weight"
                type="number"
                min="1"
                class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
              />
            </label>
          </div>
          <label class="flex items-center gap-3 text-sm font-medium text-slate-300">
            <input
              v-model="membershipForm.enabled"
              type="checkbox"
              class="h-4 w-4 rounded border-slate-600 bg-slate-950 text-sky-500 focus:ring-sky-400"
            />
            Membership habilitada
          </label>
        </div>

        <div class="mt-4 flex items-center gap-3">
          <button
            type="button"
            class="rounded-lg border border-amber-400/40 bg-amber-500/10 px-4 py-2 text-sm font-semibold text-amber-100 transition hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="membershipBusy || !membershipForm.groupId || !membershipForm.agentId"
            @click="saveMembership"
          >
            {{ membershipBusy ? "Salvando..." : "Salvar membership" }}
          </button>
        </div>

        <div v-if="membershipMessage" class="mt-3 text-sm text-emerald-300">
          {{ membershipMessage }}
        </div>
        <div v-if="membershipError" class="mt-3 text-sm text-rose-300">
          {{ membershipError }}
        </div>

        <div
          v-if="hasMemberships"
          class="mt-4 overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50"
        >
          <table class="min-w-full divide-y divide-slate-800 text-sm">
            <thead class="text-slate-400">
              <tr>
                <th class="px-4 py-3 text-left font-medium">Grupo / Agente</th>
                <th class="px-4 py-3 text-left font-medium">Priority</th>
                <th class="px-4 py-3 text-left font-medium">Weight</th>
                <th class="px-4 py-3 text-left font-medium">Estado</th>
                <th class="px-4 py-3 text-right font-medium"></th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800">
              <tr
                v-for="membership in memberships"
                :key="membershipKey(membership.groupId, membership.agentId)"
                class="hover:bg-slate-900/70"
              >
                <td class="px-4 py-3">
                  <div class="font-semibold text-slate-100">
                    {{ membership.groupName || membership.groupId }}
                  </div>
                  <div class="mt-1 text-xs text-slate-400">
                    {{ membership.agentIdentification || membership.agentId }}
                  </div>
                  <div class="mt-1 font-mono text-xs text-slate-500">
                    {{ membership.agentId }}
                  </div>
                </td>
                <td class="px-4 py-3 text-slate-300">{{ membership.priority }}</td>
                <td class="px-4 py-3 text-slate-300">{{ membership.weight }}</td>
                <td class="px-4 py-3">
                  <div class="flex flex-col gap-1">
                    <span
                      class="rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide"
                      :class="
                        membership.enabled
                          ? 'border border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
                          : 'border border-slate-600 bg-slate-800/70 text-slate-300'
                      "
                    >
                      {{ membership.enabled ? "enabled" : "disabled" }}
                    </span>
                    <span
                      class="rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide"
                      :class="
                        isAgentConnected(membership.agentId)
                          ? 'border border-sky-500/30 bg-sky-500/10 text-sky-200'
                          : 'border border-slate-600 bg-slate-800/70 text-slate-400'
                      "
                    >
                      {{ isAgentConnected(membership.agentId) ? "conectado" : "offline" }}
                    </span>
                  </div>
                </td>
                <td class="px-4 py-3">
                  <div class="flex justify-end gap-2">
                    <button
                      type="button"
                      class="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-200 transition hover:border-amber-400 hover:text-amber-100"
                      @click="editMembership(membership)"
                    >
                      Editar
                    </button>
                    <button
                      type="button"
                      class="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-rose-200 transition hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                      :disabled="deletingMembershipKey === membershipKey(membership.groupId, membership.agentId)"
                      @click="deleteMembership(membership)"
                    >
                      {{ deletingMembershipKey === membershipKey(membership.groupId, membership.agentId) ? "Removendo..." : "Remover" }}
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
            <h3 class="text-lg font-semibold text-slate-100">Access Grants</h3>
            <p class="mt-1 text-sm text-slate-400">
              Define o que cada usuário pode acessar e por qual grupo.
            </p>
          </div>
          <button
            v-if="grantForm.id"
            type="button"
            class="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-300 transition hover:border-slate-500 hover:text-slate-100"
            @click="resetGrantForm"
          >
            Cancelar
          </button>
        </div>

        <div class="grid gap-3">
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Usuário
            <select
              v-model="grantForm.userId"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            >
              <option value="" disabled>Selecione</option>
              <option v-for="user in users" :key="user.id" :value="user.id">
                {{ user.username }}
              </option>
            </select>
          </label>
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Perfil de destino
            <select
              v-model="grantForm.destinationProfileId"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            >
              <option value="">Nenhum</option>
              <option
                v-for="profile in destinationProfiles"
                :key="profile.id"
                :value="profile.id"
              >
                {{ profile.name }}
              </option>
            </select>
          </label>
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Grupo
            <select
              v-model="grantForm.groupId"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            >
              <option value="">Nenhum</option>
              <option v-for="group in agentGroups" :key="group.id" :value="group.id">
                {{ group.name }}
              </option>
            </select>
          </label>
          <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
            Access mode
            <select
              v-model="grantForm.accessMode"
              class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
            >
              <option value="direct">direct</option>
              <option value="profile">profile</option>
            </select>
          </label>
        </div>

        <div class="mt-4 flex items-center gap-3">
          <button
            type="button"
            class="rounded-lg border border-emerald-400/40 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-100 transition hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            :disabled="grantBusy || !grantForm.userId || (!grantForm.groupId && !grantForm.destinationProfileId)"
            @click="saveGrant"
          >
            {{ grantBusy ? "Salvando..." : grantForm.id ? "Atualizar grant" : "Criar grant" }}
          </button>
        </div>

        <div v-if="grantMessage" class="mt-3 text-sm text-emerald-300">
          {{ grantMessage }}
        </div>
        <div v-if="grantError" class="mt-3 text-sm text-rose-300">
          {{ grantError }}
        </div>

        <div
          v-if="hasGrants"
          class="mt-4 overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50"
        >
          <table class="min-w-full divide-y divide-slate-800 text-sm">
            <thead class="text-slate-400">
              <tr>
                <th class="px-4 py-3 text-left font-medium">Usuário</th>
                <th class="px-4 py-3 text-left font-medium">Escopo</th>
                <th class="px-4 py-3 text-left font-medium">Modo</th>
                <th class="px-4 py-3 text-right font-medium"></th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800">
              <tr v-for="grant in grants" :key="grant.id" class="hover:bg-slate-900/70">
                <td class="px-4 py-3">
                  <div class="font-semibold text-slate-100">
                    {{ grant.username || grant.userId }}
                  </div>
                  <div v-if="grant.updatedAt" class="mt-1 text-xs text-slate-500">
                    {{ formatRelative(grant.updatedAt) }}
                  </div>
                </td>
                <td class="px-4 py-3 text-slate-300">
                  <div v-if="grant.destinationProfileName">
                    Perfil: {{ grant.destinationProfileName }}
                  </div>
                  <div v-if="grant.groupName">
                    Grupo: {{ grant.groupName }}
                  </div>
                  <div
                    v-if="!grant.destinationProfileName && !grant.groupName"
                    class="text-slate-500"
                  >
                    -
                  </div>
                </td>
                <td class="px-4 py-3 font-mono text-slate-300">
                  {{ grant.accessMode || "direct" }}
                </td>
                <td class="px-4 py-3">
                  <div class="flex justify-end gap-2">
                    <button
                      type="button"
                      class="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-200 transition hover:border-emerald-400 hover:text-emerald-100"
                      @click="editGrant(grant)"
                    >
                      Editar
                    </button>
                    <button
                      type="button"
                      class="rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-rose-200 transition hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                      :disabled="deletingGrantId === grant.id"
                      @click="deleteGrant(grant)"
                    >
                      {{ deletingGrantId === grant.id ? "Removendo..." : "Remover" }}
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <div v-if="pacError" class="mt-4 text-sm text-rose-300">
      {{ pacError }}
    </div>
    <div
      v-if="pacInfo"
      class="mt-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4"
    >
      <div class="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h3 class="text-sm font-semibold uppercase tracking-wide text-emerald-200">
            PAC do usuário {{ pacInfo.username }}
          </h3>
          <p class="mt-1 text-sm text-slate-300">
            Use este link como URL de autoconfiguração do navegador ou sistema.
          </p>
        </div>
        <a
          :href="pacInfo.pacUrl"
          target="_blank"
          rel="noreferrer"
          class="rounded-lg border border-emerald-400/40 bg-emerald-500/10 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-emerald-100 transition hover:bg-emerald-500/20"
        >
          Abrir PAC
        </a>
      </div>
      <div class="mt-3 rounded-lg border border-slate-800 bg-slate-950/70 p-3 font-mono text-xs text-slate-300 break-all">
        {{ pacInfo.pacUrl }}
      </div>
      <div class="mt-3 text-sm text-slate-300">
        <span v-if="pacInfo.catchAll">
          Este PAC está em modo catch-all porque o usuário possui grant por grupo sem perfil explícito. Tráfego com hostname não plano será enviado ao relay.
        </span>
        <span v-else>
          Este PAC só envia ao relay os destinos listados abaixo.
        </span>
      </div>
      <div v-if="pacInfo.profileHosts?.length" class="mt-3 flex flex-wrap gap-2">
        <span
          v-for="host in pacInfo.profileHosts"
          :key="host"
          class="rounded-full border border-slate-700 bg-slate-900/70 px-2 py-1 text-xs text-slate-300"
        >
          {{ host }}
        </span>
      </div>
      <div class="mt-3 text-xs text-slate-500">
        O PAC não embute credencial. O navegador ainda precisa autenticar no proxy usando o usuário do relay.
      </div>
    </div>

    <div class="mt-4 text-xs text-slate-500">
      Perfil grant restringe o alvo ao `host:port` cadastrado no perfil. Grant só com
      grupo permite acesso direto a qualquer destino dentro das ACLs do agente escolhido.
    </div>
  </section>
</template>
