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

const POLL_INTERVAL_MS = 3000
const POLL_INTERVAL_SECONDS = POLL_INTERVAL_MS / 1000

const RANGE_OPTIONS = [
  { label: '10m', minutes: 10 },
  { label: '30m', minutes: 30 },
  { label: '60m', minutes: 60 },
  { label: '1d', minutes: 1440 },
  { label: '5d', minutes: 7200 },
  { label: '7d', minutes: 10080 },
] as const

type NetworkPoint = {
  timestamp: number
  inbound: number
  outbound: number
}

const MAX_HISTORY_MINUTES = Math.max(...RANGE_OPTIONS.map((option) => option.minutes))
const MAX_NETWORK_POINTS =
  Math.ceil((MAX_HISTORY_MINUTES * 60) / POLL_INTERVAL_SECONDS) + 10

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

const hasAgents = computed(() => state.data.agents.length > 0)

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
  if (!value || value <= 0) return '0 B/s'
  return `${formatBytes(value)}/s`
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
  }, POLL_INTERVAL_MS)
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
            label: 'In (MiB/s)',
            data: [],
            borderColor: '#22d3ee',
            backgroundColor: 'rgba(34, 211, 238, 0.12)',
            fill: true,
            tension: 0.25,
            pointRadius: 0,
          },
          {
            label: 'Out (MiB/s)',
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
    inboundValues.push(point.inbound / (1024 * 1024))
    outboundValues.push(point.outbound / (1024 * 1024))
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
  const overflow = state.netHistory.length - MAX_NETWORK_POINTS
  if (overflow > 0) {
    state.netHistory.splice(0, overflow)
  }
}

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
          <div class="text-sm text-slate-400">
            Atualizado <span class="font-medium text-slate-200">{{ generatedAtLabel }}</span>
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
              <span class="font-mono text-xs text-slate-500">MiB/s</span>
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
            {{ state.data.agents.length }} conectados
          </div>
        </div>
        <div v-if="hasAgents" class="space-y-6">
          <article
            v-for="agent in state.data.agents"
            :key="agent.id"
            class="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-lg shadow-slate-950/40"
          >
            <div class="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div class="space-y-1">
                <div class="text-lg font-semibold">{{ agent.id }}</div>
                <div class="text-sm text-slate-400">
                  Remoto {{ agent.remote }} · Conectado há {{ formatRelative(agent.connectedAt) }}
                </div>
                <div v-if="agent.autoConfig" class="text-sm">
                  <a
                    :href="agent.autoConfig"
                    class="text-teal-400 transition hover:text-teal-200"
                  >
                    Download PAC
                  </a>
                </div>
              </div>
              <div class="text-sm text-slate-400 md:text-right">
                {{ agent.streams?.length ?? 0 }} streams ativas
              </div>
            </div>

            <div v-if="agent.streams?.length" class="mt-4 overflow-x-auto">
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
            <div v-else class="mt-4 rounded-lg border border-dashed border-slate-800 bg-slate-900/80 p-4 text-sm text-slate-400">
              Nenhum fluxo ativo
            </div>
          </article>
        </div>
        <div
          v-else
          class="rounded-xl border border-dashed border-slate-800 bg-slate-900/40 p-6 text-center text-slate-400"
        >
          Nenhum agente conectado.
        </div>
      </section>
    </div>
  </div>
</template>
