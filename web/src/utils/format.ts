export function toDate(value?: string): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatBytes(bytes?: number | null): string {
  const value = Number(bytes ?? 0);
  if (!value || value <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let idx = 0;
  let current = value;
  while (current >= 1024 && idx < units.length - 1) {
    current /= 1024;
    idx += 1;
  }
  const precision = idx === 0 ? 0 : 2;
  return `${current.toFixed(precision)} ${units[idx]}`;
}

export function formatRate(bytesPerSecond?: number): string {
  const value = Number(bytesPerSecond ?? 0);
  if (!value || value <= 0) return "0 Mb/s";
  const megabits = (value * 8) / 1_000_000;
  const precision =
    megabits < 1 ? 2 : megabits < 10 ? 2 : megabits < 100 ? 1 : 0;
  return `${megabits.toFixed(precision)} Mb/s`;
}

export function formatCount(value: number | string): string {
  const num = Number(value);
  if (Number.isNaN(num)) {
    return String(value ?? "-");
  }
  return num.toLocaleString();
}

export function formatPercent(value?: number | null): string {
  const val = Number(value ?? 0);
  return `${val.toFixed(1)}%`;
}

export function formatMillis(value?: number | null): string {
  const num = Number(value ?? 0);
  if (!Number.isFinite(num) || num <= 0) return "-";
  if (num < 1) return `${num.toFixed(2)} ms`;
  if (num < 10) return `${num.toFixed(2)} ms`;
  if (num < 100) return `${num.toFixed(1)} ms`;
  return `${num.toFixed(0)} ms`;
}

export function formatRelative(input: string): string {
  const date = toDate(input);
  if (!date) return "-";
  const diff = Date.now() - date.getTime();
  if (diff < 0) return "agora";
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s atrás`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m atrás`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h atrás`;
  const days = Math.floor(hours / 24);
  return `${days}d atrás`;
}

export function formatAbsolute(input: string): string {
  const date = toDate(input);
  if (!date) return "-";
  return date.toLocaleString();
}
