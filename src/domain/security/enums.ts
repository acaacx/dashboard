/**
 * Core enumerations for the normalized security domain.
 *
 * These are the single source of truth for scanner-independent vocabulary.
 * Adapters map vendor-specific values onto these; the UI only ever sees these.
 */

export const SCANNER_TYPES = [
  "SEMGREP",
  "TRIVY",
  "CHECKOV",
  "GITLEAKS",
  "UNKNOWN",
] as const;

export type ScannerType = (typeof SCANNER_TYPES)[number];

export const FINDING_CATEGORIES = [
  "SAST",
  "SCA",
  "SECRET",
  "IAC",
  "CONTAINER",
  "CONFIGURATION",
  "DAST",
  "OTHER",
] as const;

export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

export const SEVERITIES = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
  "UNKNOWN",
] as const;

export type Severity = (typeof SEVERITIES)[number];

export const FINDING_STATUSES = [
  "OPEN",
  "RESOLVED",
  "ACCEPTED_RISK",
  "FALSE_POSITIVE",
  "SUPPRESSED",
] as const;

export type FindingStatus = (typeof FINDING_STATUSES)[number];

/**
 * Result of reconciling an incoming finding against what is already stored.
 * This is a transition label, not a persisted status: a NEW or REOPENED
 * finding is stored with status OPEN.
 */
export const FINDING_TRANSITIONS = [
  "NEW",
  "EXISTING",
  "REOPENED",
  "RESOLVED",
] as const;

export type FindingTransition = (typeof FINDING_TRANSITIONS)[number];

/** Sort weight for severities. Higher is worse. Used for ordering, never for scoring. */
export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
  UNKNOWN: 0,
};

/**
 * Severities that count toward "open risk" headline numbers.
 * INFO and UNKNOWN are deliberately excluded from the donut chart's four slices
 * but are still counted in totals.
 */
export const CHARTED_SEVERITIES: readonly Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
];

/** Statuses that mean "this is still an open risk on the board". */
export const OPEN_STATUSES: readonly FindingStatus[] = ["OPEN"];

/** Human labels. Extending a scanner does not require touching the UI: unknown
 * keys fall back to a title-cased version of the enum value. */
const SCANNER_LABELS: Partial<Record<string, string>> = {
  SEMGREP: "Semgrep",
  TRIVY: "Trivy",
  CHECKOV: "Checkov",
  GITLEAKS: "Gitleaks",
  UNKNOWN: "Unknown",
};

const CATEGORY_LABELS: Partial<Record<string, string>> = {
  SAST: "SAST",
  SCA: "SCA",
  SECRET: "Secret",
  IAC: "IaC",
  CONTAINER: "Container",
  CONFIGURATION: "Configuration",
  DAST: "DAST",
  OTHER: "Other",
};

const STATUS_LABELS: Partial<Record<string, string>> = {
  OPEN: "Open",
  RESOLVED: "Resolved",
  ACCEPTED_RISK: "Accepted risk",
  FALSE_POSITIVE: "False positive",
  SUPPRESSED: "Suppressed",
};

function titleCase(value: string): string {
  return value
    .toLowerCase()
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function scannerLabel(scanner: string): string {
  return SCANNER_LABELS[scanner] ?? titleCase(scanner);
}

export function categoryLabel(category: string): string {
  return CATEGORY_LABELS[category] ?? titleCase(category);
}

export function statusLabel(status: string): string {
  return STATUS_LABELS[status] ?? titleCase(status);
}

export function severityLabel(severity: string): string {
  return titleCase(severity);
}

export function isScannerType(value: unknown): value is ScannerType {
  return (
    typeof value === "string" &&
    (SCANNER_TYPES as readonly string[]).includes(value)
  );
}

export function isSeverity(value: unknown): value is Severity {
  return (
    typeof value === "string" && (SEVERITIES as readonly string[]).includes(value)
  );
}

export function isFindingCategory(value: unknown): value is FindingCategory {
  return (
    typeof value === "string" &&
    (FINDING_CATEGORIES as readonly string[]).includes(value)
  );
}

export function isFindingStatus(value: unknown): value is FindingStatus {
  return (
    typeof value === "string" &&
    (FINDING_STATUSES as readonly string[]).includes(value)
  );
}
