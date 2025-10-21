<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { Chart, registerables } from 'chart.js'
import type { ChartDataset, ChartOptions } from 'chart.js'

Chart.register(...registerables)

type ResourcePoint = {
  timestamp: string
  cpuPercent: number
  rssBytes: number
  goroutines: number
}

type ResourceSnapshot = {
  current: ResourcePoint
  history: ResourcePoint[]
}

type StatusStream = {
  streamId: string
  target: string
  protocol: string
  createdAt: string
  bytesUp: number
  bytesDown: number
}

type StatusAgent = {
  id: string
  remote: string
  connectedAt: string
  streams: StatusStream[]
  autoConfig?: string
}

type StatusMetrics = {
  agentsConnected: number
  activeStreams: number
  bytesUp: number
  bytesDown: number
  dialErrors: number
  authFailures: number
}

type StatusPayload = {
  generatedAt: string
  proxyAddr: string
  secureAddr: string
  socksAddr: string
  acmeHosts: string[]
  agents: StatusAgent[]
  metrics: StatusMetrics
  resources: ResourceSnapshot
}

type NetworkRates = {
  in: number
  out: number
}

type MetricsSnapshot = {
  bytesUp: number
  bytesDown: number
  timestamp: number
}

const RANGE_OPTIONS = [
  { label: '10m', minutes: 10 },
  { label: '30m', minutes: 30 },
  { label: '60m', minutes: 60 },
  { label: '1d', minutes: 1440 },
  { label: '5d', minutes: 7200 },
  { label: '7d', minutes: 10080 },
] as const

const REFRESH_OPTIONS = [
  { label: '0.5s', ms: 500 },
  { label: '1s', ms: 1000 },
  { label: '2s', ms: 2000 },
  { label: '3s', ms: 3000 },
  { label: '5s', ms: 5000 },
  { label: '10s', ms: 10000 },
] as const

type NetworkPoint = {
  timestamp: number
  inbound: number
  outbound: number
}

const MAX_HISTORY_MINUTES = Math.max(...RANGE_OPTIONS.map((option) => option.minutes))

const emptyPoint: ResourcePoint = {
  timestamp: '',
  cpuPercent: 0,
  rssBytes: 0,
  goroutines: 0,
}

const emptyStatus: StatusPayload = {
  generatedAt: '',
  proxyAddr: '',
  secureAddr: '',
  socksAddr: '',
  acmeHosts: [],
  agents: [],
  metrics: {
    agentsConnected: 0,
    activeStreams: 0,
    bytesUp: 0,
    bytesDown: 0,
    dialErrors: 0,
    authFailures: 0,
  },
  resources: {
    current: { ...emptyPoint },
    history: [],
  },
}

declare global {
  interface Window {
    STATUS_BOOTSTRAP?: StatusPayload
  }
}

const state = reactive<{
  data: StatusPayload
  rangeMinutes: number
  netRates: NetworkRates
  lastMetrics: MetricsSnapshot | null
  netHistory: NetworkPoint[]
}>({
  data: normalizePayload(window.STATUS_BOOTSTRAP),
  rangeMinutes: 60,
  netRates: { in: 0, out: 0 },
  lastMetrics: null,
  netHistory: [],
})

const cpuCanvas = ref<HTMLCanvasElement | null>(null)
const memCanvas = ref<HTMLCanvasElement | null>(null)
const networkCanvas = ref<HTMLCanvasElement | null>(null)
let cpuChart: Chart<'line'> | null = null
let memChart: Chart<'line'> | null = null
let networkChart: Chart<'line'> | null = null
let pollTimer: number | null = null

const refreshIntervalMs = ref<number>(3000)
const refreshMenuOpen = ref(false)
const maxNetworkPoints = computed(() =>
  Math.ceil((MAX_HISTORY_MINUTES * 60 * 1000) / refreshIntervalMs.value) + 10,
)
const selectedRefreshLabel = computed(() => {
  const match = REFRESH_OPTIONS.find((option) => option.ms === refreshIntervalMs.value)
  if (match) {
    return match.label
  }
  const seconds = refreshIntervalMs.value / 1000
  return seconds < 1 ? `${seconds.toFixed(2)}s` : `${seconds.toFixed(1)}s`
})

const agentSearch = ref('')
const connectionSearch = ref('')
const selectedConnectionCount = ref<number | null>(null)
const expandedAgents = ref<Set<string>>(new Set())

const summaryCards = computed(() => {
  const metrics = state.data.metrics
  const resources = state.data.resources.current
  return [
    { label: 'Agentes Conectados', value: formatCount(metrics.agentsConnected) },
    { label: 'Streams Ativas', value: formatCount(metrics.activeStreams) },
    { label: 'CPU', value: formatPercent(resources.cpuPercent) },
    { label: 'Memória RSS', value: formatBytes(resources.rssBytes) },
    { label: 'Rede In', value: formatRate(state.netRates.in) },
    { label: 'Rede Out', value: formatRate(state.netRates.out) },
    { label: 'Bytes (cliente → intranet)', value: formatBytes(metrics.bytesUp) },
    { label: 'Bytes (intranet → cliente)', value: formatBytes(metrics.bytesDown) },
    { label: 'Falhas de Dial', value: formatCount(metrics.dialErrors) },
    { label: 'Falhas de Autenticação', value: formatCount(metrics.authFailures) },
  ]
})

const connectionOptions = computed(() => {
  const counts = new Map<number, number>()
  state.data.agents.forEach((agent) => {
    const count = agent.streams?.length ?? 0
    counts.set(count, (counts.get(count) ?? 0) + 1)
  })
  return Array.from(counts.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([count, total]) => ({
      count,
      total,
      label: `${count} ${count === 1 ? 'conexão' : 'conexões'} (${total})`,
    }))
})

const filteredConnectionOptions = computed(() => {
  const query = connectionSearch.value.trim().toLowerCase()
  if (!query) return connectionOptions.value
  return connectionOptions.value.filter((option) =>
    option.label.toLowerCase().includes(query),
  )
})

const filteredAgents = computed(() => {
  const query = agentSearch.value.trim().toLowerCase()
  const requiredConnections = selectedConnectionCount.value
  return state.data.agents.filter((agent) => {
    const streamCount = agent.streams?.length ?? 0
    if (requiredConnections !== null && streamCount !== requiredConnections) {
      return false
    }
    if (!query) return true
    const haystack = `${agent.id} ${agent.remote}`.toLowerCase()
    return haystack.includes(query)
  })
})

const hasAgents = computed(() => filteredAgents.value.length > 0)

const generatedAtLabel = computed(() =>
  formatAbsolute(state.data.generatedAt),
)

function normalizePayload(payload?: StatusPayload): StatusPayload {
  if (!payload) {
    return {
      ...emptyStatus,
      metrics: { ...emptyStatus.metrics },
      resources: {
        current: { ...emptyStatus.resources.current },
        history: [],
      },
      agents: [],
      acmeHosts: [],
    }
  }
  return {
    generatedAt: payload.generatedAt ?? '',
    proxyAddr: payload.proxyAddr ?? '',
    secureAddr: payload.secureAddr ?? '',
    socksAddr: payload.socksAddr ?? '',
    acmeHosts: payload.acmeHosts ?? [],
    agents: payload.agents ?? [],
    metrics: {
      agentsConnected: payload.metrics?.agentsConnected ?? 0,
      activeStreams: payload.metrics?.activeStreams ?? 0,
      bytesUp: payload.metrics?.bytesUp ?? 0,
      bytesDown: payload.metrics?.bytesDown ?? 0,
      dialErrors: payload.metrics?.dialErrors ?? 0,
      authFailures: payload.metrics?.authFailures ?? 0,
    },
    resources: {
      current: {
        timestamp: payload.resources?.current?.timestamp ?? '',
        cpuPercent: payload.resources?.current?.cpuPercent ?? 0,
        rssBytes: payload.resources?.current?.rssBytes ?? 0,
        goroutines: payload.resources?.current?.goroutines ?? 0,
      },
      history: payload.resources?.history ?? [],
    },
  }
}

function formatBytes(bytes?: number | null): string {
  const value = Number(bytes ?? 0)
  if (!value || value <= 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let idx = 0
  let current = value
  while (current >= 1024 && idx < units.length - 1) {
    current /= 1024
    idx += 1
  }
  const precision = idx === 0 ? 0 : 2
  return `${current.toFixed(precision)} ${units[idx]}`
}

function formatRate(bytesPerSecond?: number): string {
  const value = Number(bytesPerSecond ?? 0)
  if (!value || value <= 0) return '0 Mb/s'
  const megabits = (value * 8) / 1_000_000
  const precision = megabits < 1 ? 2 : megabits < 10 ? 2 : megabits < 100 ? 1 : 0
  return `${megabits.toFixed(precision)} Mb/s`
}

function formatCount(value: number | string): string {
  const num = Number(value)
  if (Number.isNaN(num)) {
    return String(value ?? '-')
  }
  return num.toLocaleString()
}

function formatPercent(value?: number | null): string {
  const val = Number(value ?? 0)
  return `${val.toFixed(1)}%`
}

function formatRelative(input: string): string {
  const date = toDate(input)
  if (!date) return '-'
  const diff = Date.now() - date.getTime()
  if (diff < 0) return 'agora'
  const seconds = Math.floor(diff / 1000)
  if (seconds < 60) return `${seconds}s atrás`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m atrás`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h atrás`
  const days = Math.floor(hours / 24)
  return `${days}d atrás`
}

function formatAbsolute(input: string): string {
  const date = toDate(input)
  if (!date) return '-'
  return date.toLocaleString()
}

function toDate(value?: string): Date | null {
  if (!value) return null
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

function rangeButtonClass(minutes: number): string {
  const active = state.rangeMinutes === minutes
  const base =
    'px-3 py-1.5 rounded-full text-sm font-medium transition-colors border'
  if (active) {
    return `${base} border-sky-400 bg-sky-500/20 text-sky-100`
  }
  return `${base} border-slate-700 text-slate-300 hover:text-slate-100 hover:border-slate-500`
}

function schedulePoll() {
  pollTimer = window.setTimeout(async () => {
    try {
      const res = await fetch('/status.json', { cache: 'no-store' })
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`)
      }
      const payload = (await res.json()) as StatusPayload
      state.data = normalizePayload(payload)
    } catch (err) {
      console.warn('status refresh failed', err)
    } finally {
      schedulePoll()
    }
  }, refreshIntervalMs.value)
}

function restartPolling() {
  if (pollTimer) {
    window.clearTimeout(pollTimer)
    pollTimer = null
  }
  schedulePoll()
}

function sliceHistory(history: ResourcePoint[]): ResourcePoint[] {
  if (!history?.length) return []
  const samplesPerMinute = 1
  const maxPoints = Math.max(1, Math.round(state.rangeMinutes * samplesPerMinute))
  if (history.length <= maxPoints) return [...history]
  return history.slice(history.length - maxPoints)
}

function sliceNetworkHistory(history: NetworkPoint[]): NetworkPoint[] {
  if (!history?.length) return []
  const cutoff = Date.now() - state.rangeMinutes * 60 * 1000
  return history.filter((point) => point.timestamp >= cutoff)
}

function buildHistory(
  history: ResourcePoint[],
  mapper: (point: ResourcePoint) => number,
) {
  const windowed = sliceHistory(history)
  const labels: string[] = []
  const values: number[] = []
  windowed.forEach((point) => {
    labels.push(formatChartTimestamp(point.timestamp))
    values.push(mapper(point))
  })
  return { labels, values }
}

function formatChartTimestamp(input: string): string {
  const date = toDate(input)
  if (!date) return '-'
  if (state.rangeMinutes <= 30) {
    return date.toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }
  if (state.rangeMinutes <= 1440) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }
  const datePart = date.toLocaleDateString()
  const timePart = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  return `${datePart} ${timePart}`
}

function ensureCharts() {
  if (!cpuChart && cpuCanvas.value) {
    cpuChart = new Chart(cpuCanvas.value, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'CPU %',
            data: [],
            borderColor: '#38bdf8',
            backgroundColor: 'rgba(56, 189, 248, 0.15)',
            fill: true,
            tension: 0.1,
            pointRadius: 0,
          } satisfies ChartDataset<'line'>,
        ],
      },
      options: chartOptions(),
    })
  }
  if (!memChart && memCanvas.value) {
    memChart = new Chart(memCanvas.value, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'RSS MiB',
            data: [],
            borderColor: '#f97316',
            backgroundColor: 'rgba(249, 115, 22, 0.15)',
            fill: true,
            tension: 0.1,
            pointRadius: 0,
          } satisfies ChartDataset<'line'>,
        ],
      },
      options: chartOptions(),
    })
  }
  if (!networkChart && networkCanvas.value) {
    networkChart = new Chart(networkCanvas.value, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'In (Mb/s)',
            data: [],
            borderColor: '#22d3ee',
            backgroundColor: 'rgba(34, 211, 238, 0.12)',
            fill: true,
            tension: 0.25,
            pointRadius: 0,
          },
          {
            label: 'Out (Mb/s)',
            data: [],
            borderColor: '#c084fc',
            backgroundColor: 'rgba(192, 132, 252, 0.12)',
            fill: true,
            tension: 0.25,
            pointRadius: 0,
          },
        ] satisfies ChartDataset<'line'>[],
      },
      options: chartOptions({ stacked: false }),
    })
  }
}

function chartOptions({ stacked = false }: { stacked?: boolean } = {}): ChartOptions<'line'> {
  return {
    animation: false,
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: {
        ticks: {
          color: '#94a3b8',
          maxRotation: 45,
          minRotation: 45,
        },
        grid: {
          color: 'rgba(148, 163, 184, 0.1)',
        },
      },
      y: {
        beginAtZero: true,
        stacked,
        ticks: {
          color: '#94a3b8',
        },
        grid: {
          color: 'rgba(148, 163, 184, 0.1)',
        },
      },
    },
    plugins: {
      legend: {
        labels: {
          color: '#cbd5f5',
        },
      },
    },
  }
}

function updateCharts(data: StatusPayload) {
  ensureCharts()
  if (!cpuChart || !memChart) return

  const history = data.resources.history ?? []
  const cpuData = buildHistory(history, (point) => point.cpuPercent)
  const memData = buildHistory(history, (point) => point.rssBytes / (1024 * 1024))

  cpuChart.data.labels = cpuData.labels
  cpuChart.data.datasets[0].data = cpuData.values
  cpuChart.update('none')

  memChart.data.labels = memData.labels
  memChart.data.datasets[0].data = memData.values
  memChart.update('none')

  if (!networkChart) return

  const networkWindow = sliceNetworkHistory(state.netHistory)
  const netLabels: string[] = []
  const inboundValues: number[] = []
  const outboundValues: number[] = []
  networkWindow.forEach((point) => {
    netLabels.push(
      formatChartTimestamp(new Date(point.timestamp).toISOString()),
    )
    inboundValues.push((point.inbound * 8) / 1_000_000)
    outboundValues.push((point.outbound * 8) / 1_000_000)
  })

  networkChart.data.labels = netLabels
  networkChart.data.datasets[0].data = inboundValues
  networkChart.data.datasets[1].data = outboundValues
  networkChart.update('none')
}

function updateNetworkRates(data: StatusPayload) {
  const metrics = data.metrics
  const now = toDate(data.generatedAt)?.getTime() ?? Date.now()
  if (state.lastMetrics) {
    const dt = (now - state.lastMetrics.timestamp) / 1000
    if (dt > 0) {
      const inbound = metrics.bytesUp - state.lastMetrics.bytesUp
      const outbound = metrics.bytesDown - state.lastMetrics.bytesDown
      state.netRates.in = Math.max(inbound / dt, 0)
      state.netRates.out = Math.max(outbound / dt, 0)
    } else {
      state.netRates.in = 0
      state.netRates.out = 0
    }
  }
  state.lastMetrics = {
    bytesUp: metrics.bytesUp,
    bytesDown: metrics.bytesDown,
    timestamp: now,
  }

  appendNetworkHistory(now, state.netRates)
}

function appendNetworkHistory(timestamp: number, rates: NetworkRates) {
  state.netHistory.push({
    timestamp,
    inbound: rates.in,
    outbound: rates.out,
  })
  const overflow = state.netHistory.length - maxNetworkPoints.value
  if (overflow > 0) {
    state.netHistory.splice(0, overflow)
  }
}

watch(connectionOptions, (options) => {
  if (
    selectedConnectionCount.value !== null &&
    !options.some((option) => option.count === selectedConnectionCount.value)
  ) {
    selectedConnectionCount.value = null
  }
})

watch(refreshIntervalMs, () => {
  restartPolling()
})

watch(
  () => state.data,
  (data) => {
    updateNetworkRates(data)
    updateCharts(data)
  },
  { immediate: true },
)

watch(
  () => state.rangeMinutes,
  () => updateCharts(state.data),
)

watch(
  () => state.data.agents.map((agent) => agent.id),
  (ids) => {
    const available = new Set(ids)
    const current = expandedAgents.value
    const next = new Set<string>()
    current.forEach((id) => {
      if (available.has(id)) {
        next.add(id)
      }
    })
    expandedAgents.value = next
  },
)

onMounted(() => {
  ensureCharts()
  schedulePoll()
})

onBeforeUnmount(() => {
  if (pollTimer) {
    window.clearTimeout(pollTimer)
  }
  cpuChart?.destroy()
  memChart?.destroy()
  networkChart?.destroy()
  cpuChart = null
  memChart = null
  networkChart = null
})

function toggleAgent(agentId: string) {
  const next = new Set(expandedAgents.value)
  if (next.has(agentId)) {
    next.delete(agentId)
  } else {
    next.add(agentId)
  }
  expandedAgents.value = next
}

function isExpanded(agentId: string) {
  return expandedAgents.value.has(agentId)
}

function selectConnectionCount(count: number | null) {
  if (selectedConnectionCount.value === count) {
    selectedConnectionCount.value = null
  } else {
    selectedConnectionCount.value = count
  }
}

function chipClass(active: boolean): string {
  const base =
    'rounded-full border px-3 py-1.5 text-sm font-medium transition-colors'
  if (active) {
    return `${base} border-sky-400 bg-sky-500/20 text-sky-100`
  }
  return `${base} border-slate-700 text-slate-300 hover:border-slate-500 hover:text-slate-100`
}

function clearConnectionFilters() {
  selectedConnectionCount.value = null
  connectionSearch.value = ''
}

function selectRefreshInterval(ms: number) {
  refreshIntervalMs.value = ms
  refreshMenuOpen.value = false
}
</script>

<template>
  <div class="min-h-screen bg-slate-950 text-slate-100">
    <div class="mx-auto flex max-w-6xl flex-col gap-10 px-4 py-8">
      <header class="space-y-4">
        <h1 class="text-3xl font-semibold tracking-tight">Intratun Relay</h1>
        <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <div class="text-sm text-slate-400">Proxy (HTTP CONNECT)</div>
            <div class="mt-1 font-mono text-lg">
              {{ state.data.proxyAddr || 'desabilitado' }}
            </div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <div class="text-sm text-slate-400">Secure (WSS / Metrics)</div>
            <div class="mt-1 font-mono text-lg">
              {{ state.data.secureAddr || '-' }}
            </div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <div class="text-sm text-slate-400">SOCKS5</div>
            <div class="mt-1 font-mono text-lg">
              {{ state.data.socksAddr || 'desabilitado' }}
            </div>
          </div>
        </div>
        <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div class="mb-2 text-sm text-slate-400">ACME Hosts</div>
          <div class="font-mono text-sm">
            {{ state.data.acmeHosts.length ? state.data.acmeHosts.join(' ') : '-' }}
          </div>
        </div>
      </header>

      <section>
        <div class="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <h2 class="text-xl font-semibold">Resumo</h2>
          <div class="flex flex-col items-start gap-2 text-sm text-slate-400 sm:flex-row sm:items-center sm:gap-4">
            <div>
              Atualizado <span class="font-medium text-slate-200">{{ generatedAtLabel }}</span>
            </div>
            <div class="relative">
              <button
                type="button"
                class="flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900/80 px-3 py-1.5 text-xs font-medium uppercase tracking-wide text-slate-200 transition hover:border-slate-500 hover:text-slate-100"
                @click="refreshMenuOpen = !refreshMenuOpen"
                @keydown.escape="refreshMenuOpen = false"
              >
                <span class="text-[11px] font-semibold text-slate-400">Atualizar a cada</span>
                <span class="font-mono text-sm text-slate-100">{{ selectedRefreshLabel }}</span>
                <span class="text-slate-500" :class="refreshMenuOpen ? 'rotate-180 transform transition' : 'transition'">▾</span>
              </button>
              <div
                v-if="refreshMenuOpen"
                class="absolute right-0 z-10 mt-2 w-40 overflow-hidden rounded-lg border border-slate-800 bg-slate-950/95 shadow-lg shadow-slate-950/40 backdrop-blur"
              >
                <button
                  v-for="option in REFRESH_OPTIONS"
                  :key="option.ms"
                  type="button"
                  class="flex w-full items-center justify-between px-3 py-2 text-left text-sm transition"
                  :class="option.ms === refreshIntervalMs ? 'bg-sky-500/20 text-sky-100' : 'text-slate-200 hover:bg-slate-900/80'"
                  @click="selectRefreshInterval(option.ms)"
                >
                  <span class="font-mono text-sm">{{ option.label }}</span>
                  <span v-if="option.ms === refreshIntervalMs" class="text-xs text-sky-200">ativo</span>
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

      <section>
        <div class="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <h2 class="text-xl font-semibold">Recursos</h2>
          <div class="flex flex-wrap gap-2">
            <button
              v-for="option in RANGE_OPTIONS"
              :key="option.minutes"
              type="button"
              :class="rangeButtonClass(option.minutes)"
              @click="state.rangeMinutes = option.minutes"
            >
              {{ option.label }}
            </button>
          </div>
        </div>
        <div class="grid gap-4 lg:grid-cols-2">
          <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <div class="h-48">
              <canvas ref="cpuCanvas"></canvas>
            </div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <div class="h-48">
              <canvas ref="memCanvas"></canvas>
            </div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-900/60 p-4 lg:col-span-2">
            <div class="mb-2 flex items-center justify-between text-sm text-slate-400">
              <span>Tráfego de Rede</span>
              <span class="font-mono text-xs text-slate-500">Mb/s</span>
            </div>
            <div class="h-48">
              <canvas ref="networkCanvas"></canvas>
            </div>
          </div>
        </div>
      </section>

      <section>
        <div class="mb-4 flex items-center justify-between">
          <h2 class="text-xl font-semibold">Agentes</h2>
          <div class="text-sm text-slate-400">
            {{ filteredAgents.length }} de {{ state.data.agents.length }} conectados
          </div>
        </div>
        <div class="grid gap-4 rounded-xl border border-slate-800 bg-slate-900/40 p-4">
          <div class="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
            <label class="flex flex-col gap-2 text-sm font-medium text-slate-300">
              Buscar agente
              <input
                v-model="agentSearch"
                type="search"
                placeholder="ID ou endereço remoto"
                class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
              >
            </label>
            <div class="flex flex-col gap-2">
              <div class="flex items-center justify-between text-sm font-medium text-slate-300">
                <span>Filtrar por conexões</span>
                <button
                  v-if="selectedConnectionCount !== null || connectionSearch"
                  type="button"
                  class="text-xs font-semibold uppercase tracking-wide text-slate-400 hover:text-slate-200"
                  @click="clearConnectionFilters"
                >
                  Limpar
                </button>
              </div>
              <input
                v-model="connectionSearch"
                type="search"
                placeholder="Buscar quantidade, ex: 2"
                class="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-400"
              >
              <div class="flex flex-wrap gap-2">
                <button
                  v-for="option in filteredConnectionOptions"
                  :key="option.count"
                  type="button"
                  :class="chipClass(selectedConnectionCount === option.count)"
                  @click="selectConnectionCount(option.count)"
                >
                  {{ option.label }}
                </button>
                <p v-if="!filteredConnectionOptions.length" class="text-xs text-slate-500">
                  Nenhuma quantidade correspondente.
                </p>
              </div>
            </div>
          </div>
        </div>
        <div v-if="hasAgents" class="space-y-4">
          <article
            v-for="agent in filteredAgents"
            :key="agent.id"
            class="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60 shadow-lg shadow-slate-950/40"
          >
            <button
              type="button"
              class="flex w-full items-start justify-between gap-4 border-b border-slate-800 bg-slate-900/70 px-5 py-4 text-left transition hover:bg-slate-900/90"
              @click="toggleAgent(agent.id)"
            >
              <div class="space-y-1">
                <div class="text-lg font-semibold text-slate-100">{{ agent.id }}</div>
                <div class="text-sm text-slate-400">
                  Remoto {{ agent.remote }} · Conectado há {{ formatRelative(agent.connectedAt) }}
                </div>
              </div>
              <div class="flex items-center gap-3">
                <span class="rounded-full bg-slate-800/80 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-slate-300">
                  {{ agent.streams?.length ?? 0 }} {{ (agent.streams?.length ?? 0) === 1 ? 'stream' : 'streams' }}
                </span>
                <span
                  class="text-slate-500 transition-transform"
                  :class="isExpanded(agent.id) ? 'rotate-90' : ''"
                >
                  ▶
                </span>
              </div>
            </button>
            <div v-if="isExpanded(agent.id)" class="space-y-4 px-5 py-4">
              <div class="grid gap-2 text-sm text-slate-300 md:grid-cols-2">
                <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                  <div class="text-xs uppercase tracking-wide text-slate-500">ID</div>
                  <div class="font-mono text-sm text-slate-100">{{ agent.id }}</div>
                </div>
                <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                  <div class="text-xs uppercase tracking-wide text-slate-500">Remoto</div>
                  <div class="font-mono text-sm text-slate-100 break-all">{{ agent.remote }}</div>
                </div>
                <div class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                  <div class="text-xs uppercase tracking-wide text-slate-500">Conectado</div>
                  <div>{{ formatAbsolute(agent.connectedAt) }}</div>
                </div>
                <div v-if="agent.autoConfig" class="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                  <div class="text-xs uppercase tracking-wide text-slate-500">Auto Config</div>
                  <a
                    :href="agent.autoConfig"
                    class="text-teal-400 transition hover:text-teal-200"
                  >
                    Download PAC
                  </a>
                </div>
              </div>

              <div v-if="agent.streams?.length" class="overflow-x-auto">
                <table class="min-w-full divide-y divide-slate-800 text-sm">
                  <thead class="text-slate-400">
                    <tr>
                      <th class="px-3 py-2 text-left font-medium">Stream</th>
                      <th class="px-3 py-2 text-left font-medium">Destino</th>
                      <th class="px-3 py-2 text-left font-medium">Protocolo</th>
                      <th class="px-3 py-2 text-left font-medium">Criada</th>
                      <th class="px-3 py-2 text-left font-medium">⬆ Bytes</th>
                      <th class="px-3 py-2 text-left font-medium">⬇ Bytes</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-slate-800">
                    <tr
                      v-for="stream in agent.streams"
                      :key="stream.streamId"
                      class="hover:bg-slate-900/80"
                    >
                      <td class="px-3 py-2 font-mono text-xs text-slate-200">
                        {{ stream.streamId }}
                      </td>
                      <td class="px-3 py-2 font-mono text-xs text-slate-300">
                        {{ stream.target }}
                      </td>
                      <td class="px-3 py-2 uppercase text-slate-200">
                        {{ stream.protocol }}
                      </td>
                      <td class="px-3 py-2 text-slate-300">
                        {{ formatRelative(stream.createdAt) }}
                      </td>
                      <td class="px-3 py-2 text-slate-300">
                        {{ formatBytes(stream.bytesUp) }}
                      </td>
                      <td class="px-3 py-2 text-slate-300">
                        {{ formatBytes(stream.bytesDown) }}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div v-else class="rounded-lg border border-dashed border-slate-800 bg-slate-900/80 p-4 text-sm text-slate-400">
                Nenhum fluxo ativo
              </div>
            </div>
          </article>
        </div>
        <div
          v-else
          class="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 p-6 text-center text-slate-400"
        >
          Nenhum agente encontrado.
        </div>
      </section>
    </div>
  </div>
</template>
