/**
 * Formatting helpers.
 *
 * Kept out of components so every surface renders a timestamp the same way, and
 * so the fallbacks for missing or malformed values are decided once.
 */

const UNITS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ["year", 365 * 24 * 3600_000],
  ["month", 30 * 24 * 3600_000],
  ["day", 24 * 3600_000],
  ["hour", 3600_000],
  ["minute", 60_000],
];

const relativeFormatter = new Intl.RelativeTimeFormat("en", {
  numeric: "auto",
});

/** "8 min ago" style. Returns "—" for missing or unparseable input. */
export function relativeTime(
  iso: string | undefined,
  now: Date = new Date(),
): string {
  if (!iso) return "—";
  const timestamp = Date.parse(iso);
  if (!Number.isFinite(timestamp)) return "—";

  const delta = timestamp - now.getTime();
  const magnitude = Math.abs(delta);

  if (magnitude < 60_000) return "just now";

  for (const [unit, ms] of UNITS) {
    if (magnitude >= ms) {
      return relativeFormatter.format(Math.round(delta / ms), unit);
    }
  }
  return "just now";
}

const dateTimeFormatter = new Intl.DateTimeFormat("en-GB", {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  timeZone: "UTC",
});

/** Absolute UTC timestamp, for detail views and tooltips. */
export function formatDateTime(iso: string | undefined): string {
  if (!iso) return "—";
  const timestamp = Date.parse(iso);
  if (!Number.isFinite(timestamp)) return "—";
  return `${dateTimeFormatter.format(timestamp)} UTC`;
}

/** Short date, for dense table cells. */
export function formatDate(iso: string | undefined): string {
  if (!iso) return "—";
  const timestamp = Date.parse(iso);
  if (!Number.isFinite(timestamp)) return "—";
  return new Date(timestamp).toISOString().slice(0, 10);
}

/** Durations in the units an operator thinks in. */
export function formatDuration(hours: number | undefined): string {
  if (hours === undefined || !Number.isFinite(hours)) return "—";
  if (hours < 1) return `${Math.round(hours * 60)}m`;
  if (hours < 48) return `${Math.round(hours)}h`;
  return `${Math.round(hours / 24)}d`;
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat("en").format(value);
}
