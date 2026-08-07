import type { Severity } from "@/domain/security/enums";

/**
 * Severity normalization.
 *
 * Every scanner has its own vocabulary and half of them have two. This module
 * is the only place that knows about those vocabularies; adapters call in here
 * rather than mapping inline, so a new scanner's dialect is a one-line addition.
 *
 * Nothing here invents a risk score. Unmappable input becomes UNKNOWN, which
 * the UI renders honestly as "Unknown" rather than defaulting to MEDIUM.
 */

const DIRECT: Record<string, Severity> = {
  CRITICAL: "CRITICAL",
  BLOCKER: "CRITICAL",
  HIGH: "HIGH",
  IMPORTANT: "HIGH",
  MAJOR: "HIGH",
  ERROR: "HIGH",
  MEDIUM: "MEDIUM",
  MODERATE: "MEDIUM",
  WARNING: "MEDIUM",
  WARN: "MEDIUM",
  LOW: "LOW",
  MINOR: "LOW",
  INFO: "INFO",
  INFORMATIONAL: "INFO",
  NOTE: "INFO",
  NONE: "INFO",
  UNKNOWN: "UNKNOWN",
  UNTRIAGED: "UNKNOWN",
};

/**
 * SARIF `level` values (§3.27.10). SARIF has only four and they are coarse:
 * `error` is deliberately mapped to HIGH rather than CRITICAL, because
 * promoting every SARIF error to CRITICAL makes the critical count meaningless.
 * Scanners that carry finer-grained severity in `properties` override this via
 * `normalizeSecuritySeverity`.
 */
const SARIF_LEVEL: Record<string, Severity> = {
  error: "HIGH",
  warning: "MEDIUM",
  note: "LOW",
  none: "INFO",
};

/**
 * CVSS-style 0-10 score bands, matching the GitHub `security-severity`
 * property convention used by CodeQL, Semgrep and others.
 */
export function severityFromScore(score: number): Severity {
  if (!Number.isFinite(score)) return "UNKNOWN";
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0.0) return "LOW";
  return "INFO";
}

/**
 * Normalize any scanner-supplied severity token.
 *
 * Accepts strings ("HIGH", "warning"), numbers (CVSS score) and numeric
 * strings ("7.5"). Returns UNKNOWN for anything else — including null and
 * undefined, which are extremely common (Checkov omits severity in the
 * community edition, Gitleaks has no severity concept at all).
 */
export function normalizeSeverity(input: unknown): Severity {
  if (typeof input === "number") {
    return severityFromScore(input);
  }

  if (typeof input !== "string") return "UNKNOWN";

  const trimmed = input.trim();
  if (trimmed === "") return "UNKNOWN";

  const direct = DIRECT[trimmed.toUpperCase()];
  if (direct) return direct;

  // Numeric strings such as "7.5" arrive from SARIF properties, where all
  // property values are serialized as strings.
  const asNumber = Number(trimmed);
  if (!Number.isNaN(asNumber)) return severityFromScore(asNumber);

  return "UNKNOWN";
}

/** Normalize a SARIF `level`, falling back to UNKNOWN for unknown tokens. */
export function normalizeSarifLevel(level: unknown): Severity {
  if (typeof level !== "string") return "UNKNOWN";
  return SARIF_LEVEL[level.trim().toLowerCase()] ?? "UNKNOWN";
}

/**
 * Resolve severity from a SARIF result using the strongest available signal:
 * an explicit numeric `security-severity` property beats the coarse `level`.
 */
export function normalizeSecuritySeverity(
  securitySeverity: unknown,
  level: unknown,
): Severity {
  if (securitySeverity !== undefined && securitySeverity !== null) {
    const fromScore = normalizeSeverity(securitySeverity);
    if (fromScore !== "UNKNOWN") return fromScore;
  }
  return normalizeSarifLevel(level);
}

/**
 * Pick the first severity that resolves to something other than UNKNOWN.
 * Adapters use this to express precedence, e.g. "rule severity, then result
 * level, then the scanner's default".
 */
export function firstKnownSeverity(...candidates: unknown[]): Severity {
  for (const candidate of candidates) {
    const severity = normalizeSeverity(candidate);
    if (severity !== "UNKNOWN") return severity;
  }
  return "UNKNOWN";
}
