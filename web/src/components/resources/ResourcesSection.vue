<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watchEffect } from "vue";
import {
  Chart,
  type ChartDataset,
  type ChartOptions,
  registerables,
} from "chart.js";

import type {
  NetworkPoint,
  ResourcePoint,
  ResourceSnapshot,
} from "../../types/status";
import { toDate } from "../../utils/format";

Chart.register(...registerables);

const props = defineProps<{
  resources: ResourceSnapshot;
  rangeOptions: readonly { label: string; minutes: number }[];
  selectedRange: number;
  netHistory: NetworkPoint[];
}>();

const emit = defineEmits<{
  (e: "update:range", minutes: number): void;
}>();

const cpuCanvas = ref<HTMLCanvasElement | null>(null);
const memCanvas = ref<HTMLCanvasElement | null>(null);
const networkCanvas = ref<HTMLCanvasElement | null>(null);

let cpuChart: Chart<"line"> | null = null;
let memChart: Chart<"line"> | null = null;
let networkChart: Chart<"line"> | null = null;

const rangeButtonClass = (minutes: number) => {
  const active = props.selectedRange === minutes;
  const base =
    "px-3 py-1.5 rounded-full text-sm font-medium transition-colors border";
  if (active) {
    return `${base} border-sky-400 bg-sky-500/20 text-sky-100`;
  }
  return `${base} border-slate-700 text-slate-300 hover:text-slate-100 hover:border-slate-500`;
};

function sliceHistory(history: ResourcePoint[]): ResourcePoint[] {
  if (!history?.length) return [];
  const samplesPerMinute = 1;
  const maxPoints = Math.max(
    1,
    Math.round(props.selectedRange * samplesPerMinute),
  );
  if (history.length <= maxPoints) return [...history];
  return history.slice(history.length - maxPoints);
}

function sliceNetworkHistory(history: NetworkPoint[]): NetworkPoint[] {
  if (!history?.length) return [];
  const cutoff = Date.now() - props.selectedRange * 60 * 1000;
  return history.filter((point) => point.timestamp >= cutoff);
}

function buildHistory(
  history: ResourcePoint[],
  mapper: (point: ResourcePoint) => number,
) {
  const windowed = sliceHistory(history);
  const labels: string[] = [];
  const values: number[] = [];
  windowed.forEach((point) => {
    labels.push(formatChartTimestamp(point.timestamp));
    values.push(mapper(point));
  });
  return { labels, values };
}

function formatChartTimestamp(input: string): string {
  const date = toDate(input);
  if (!date) return "-";
  if (props.selectedRange <= 30) {
    return date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }
  if (props.selectedRange <= 1440) {
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  const datePart = date.toLocaleDateString();
  const timePart = date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
  return `${datePart} ${timePart}`;
}

function chartOptions({
  stacked = false,
}: { stacked?: boolean } = {}): ChartOptions<"line"> {
  return {
    animation: false,
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: {
        ticks: {
          color: "#94a3b8",
          maxRotation: 45,
          minRotation: 45,
        },
        grid: {
          color: "rgba(148, 163, 184, 0.1)",
        },
      },
      y: {
        beginAtZero: true,
        stacked,
        ticks: {
          color: "#94a3b8",
        },
        grid: {
          color: "rgba(148, 163, 184, 0.1)",
        },
      },
    },
    plugins: {
      legend: {
        labels: {
          color: "#cbd5f5",
        },
      },
    },
  };
}

function ensureCharts() {
  if (!cpuChart && cpuCanvas.value) {
    cpuChart = new Chart(cpuCanvas.value, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "CPU %",
            data: [],
            borderColor: "#38bdf8",
            backgroundColor: "rgba(56, 189, 248, 0.15)",
            fill: true,
            tension: 0.1,
            pointRadius: 0,
          } satisfies ChartDataset<"line">,
        ],
      },
      options: chartOptions(),
    });
  }
  if (!memChart && memCanvas.value) {
    memChart = new Chart(memCanvas.value, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "RSS MiB",
            data: [],
            borderColor: "#f97316",
            backgroundColor: "rgba(249, 115, 22, 0.15)",
            fill: true,
            tension: 0.1,
            pointRadius: 0,
          } satisfies ChartDataset<"line">,
        ],
      },
      options: chartOptions(),
    });
  }
  if (!networkChart && networkCanvas.value) {
    networkChart = new Chart(networkCanvas.value, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "In (Mb/s)",
            data: [],
            borderColor: "#22d3ee",
            backgroundColor: "rgba(34, 211, 238, 0.12)",
            fill: true,
            tension: 0.25,
            pointRadius: 0,
          },
          {
            label: "Out (Mb/s)",
            data: [],
            borderColor: "#c084fc",
            backgroundColor: "rgba(192, 132, 252, 0.12)",
            fill: true,
            tension: 0.25,
            pointRadius: 0,
          },
        ] satisfies ChartDataset<"line">[],
      },
      options: chartOptions({ stacked: false }),
    });
  }
}

function updateCharts() {
  ensureCharts();
  if (!cpuChart || !memChart) return;

  const history = props.resources.history ?? [];
  const cpuData = buildHistory(history, (point) => point.cpuPercent);
  const memData = buildHistory(
    history,
    (point) => point.rssBytes / (1024 * 1024),
  );

  cpuChart.data.labels = cpuData.labels;
  cpuChart.data.datasets[0].data = cpuData.values;
  cpuChart.update("none");

  memChart.data.labels = memData.labels;
  memChart.data.datasets[0].data = memData.values;
  memChart.update("none");

  if (!networkChart) return;

  const windowed = sliceNetworkHistory(props.netHistory);
  const labels: string[] = [];
  const inboundValues: number[] = [];
  const outboundValues: number[] = [];

  windowed.forEach((point) => {
    labels.push(
      formatChartTimestamp(new Date(point.timestamp).toISOString()),
    );
    inboundValues.push((point.inbound * 8) / 1_000_000);
    outboundValues.push((point.outbound * 8) / 1_000_000);
  });

  networkChart.data.labels = labels;
  networkChart.data.datasets[0].data = inboundValues;
  networkChart.data.datasets[1].data = outboundValues;
  networkChart.update("none");
}

function destroyCharts() {
  cpuChart?.destroy();
  memChart?.destroy();
  networkChart?.destroy();
  cpuChart = null;
  memChart = null;
  networkChart = null;
}

function handleRangeSelect(minutes: number) {
  emit("update:range", minutes);
}

onMounted(() => {
  ensureCharts();
  updateCharts();
});

onBeforeUnmount(() => {
  destroyCharts();
});

watchEffect(() => {
  updateCharts();
});
</script>

<template>
  <section>
    <div
      class="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
    >
      <h2 class="text-xl font-semibold">Recursos</h2>
      <div class="flex flex-wrap gap-2">
        <button
          v-for="option in rangeOptions"
          :key="option.minutes"
          type="button"
          :class="rangeButtonClass(option.minutes)"
          @click="handleRangeSelect(option.minutes)"
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
      <div
        class="rounded-lg border border-slate-800 bg-slate-900/60 p-4 lg:col-span-2"
      >
        <div
          class="mb-2 flex items-center justify-between text-sm text-slate-400"
        >
          <span>Tráfego de Rede</span>
          <span class="font-mono text-xs text-slate-500">Mb/s</span>
        </div>
        <div class="h-48">
          <canvas ref="networkCanvas"></canvas>
        </div>
      </div>
    </div>
  </section>
</template>
