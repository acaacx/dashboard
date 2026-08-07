import type {
  FindingStatus,
  Severity,
} from "@/domain/security/enums";
import type { ScannerHealthStatus } from "@/domain/security/scan-run";

/**
 * Presentation tokens for the normalized enums.
 *
 * Static, exhaustive maps rather than string interpolation: Tailwind only emits
 * classes it can see in source, so `bg-${severity}` would silently produce
 * unstyled badges. Exhaustive `Record` types also mean adding a severity is a
 * type error here rather than a blank chip in production.
 */

export const SEVERITY_CHART_COLOR: Record<Severity, string> = {
  CRITICAL: "var(--color-critical)",
  HIGH: "var(--color-high)",
  MEDIUM: "var(--color-medium)",
  LOW: "var(--color-low)",
  INFO: "var(--color-info)",
  UNKNOWN: "var(--color-unknown)",
};

export const SEVERITY_BADGE_CLASS: Record<Severity, string> = {
  CRITICAL: "border-critical/40 bg-critical/12 text-critical",
  HIGH: "border-high/40 bg-high/12 text-high",
  MEDIUM: "border-medium/40 bg-medium/12 text-medium",
  LOW: "border-low/40 bg-low/12 text-low",
  INFO: "border-info/40 bg-info/12 text-info",
  UNKNOWN: "border-unknown/40 bg-unknown/12 text-ink-faint",
};

export const SEVERITY_DOT_CLASS: Record<Severity, string> = {
  CRITICAL: "bg-critical",
  HIGH: "bg-high",
  MEDIUM: "bg-medium",
  LOW: "bg-low",
  INFO: "bg-info",
  UNKNOWN: "bg-unknown",
};

export const STATUS_BADGE_CLASS: Record<FindingStatus, string> = {
  OPEN: "border-line-strong bg-surface-raised text-ink",
  RESOLVED: "border-ok/40 bg-ok/12 text-ok",
  ACCEPTED_RISK: "border-medium/40 bg-medium/12 text-medium",
  FALSE_POSITIVE: "border-line-strong bg-surface-raised text-ink-muted",
  SUPPRESSED: "border-line-strong bg-surface-raised text-ink-faint",
};

export const HEALTH_TOKENS: Record<
  ScannerHealthStatus,
  { label: string; dot: string; text: string }
> = {
  HEALTHY: { label: "Healthy", dot: "bg-ok", text: "text-ok" },
  WARNING: { label: "Warning", dot: "bg-warn", text: "text-warn" },
  FAILED: { label: "Failed", dot: "bg-fail", text: "text-fail" },
  NEVER_RUN: {
    label: "Never run",
    dot: "bg-unknown",
    text: "text-ink-faint",
  },
};

/**
 * Distinct hues for non-severity categorical charts (scanner, category).
 * Deliberately desaturated so they never compete with the severity scale —
 * in this UI, saturated red/orange/amber means severity and nothing else.
 */
export const CATEGORICAL_COLORS = [
  "#4d9dff",
  "#22d3ee",
  "#3ddc97",
  "#a78bfa",
  "#7c8798",
  "#e2725b",
  "#5eead4",
  "#c4b5fd",
] as const;

export function categoricalColor(index: number): string {
  return CATEGORICAL_COLORS[index % CATEGORICAL_COLORS.length];
}
