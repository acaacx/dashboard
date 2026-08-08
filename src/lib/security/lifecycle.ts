import type { FindingStatus, FindingTransition } from "@/domain/security/enums";
import type { SecurityFinding } from "@/domain/security/finding";

/**
 * Finding lifecycle.
 *
 * Transitions:
 *
 *   (absent)  --scan sees it-->  NEW      -> stored as OPEN
 *   OPEN      --scan sees it-->  EXISTING -> lastDetectedAt advances
 *   OPEN      --scan misses it-> RESOLVED -> resolvedAt set
 *   RESOLVED  --scan sees it-->  REOPENED -> stored as OPEN, resolvedAt cleared
 *
 * Two rules matter more than the rest:
 *
 * 1. `firstDetectedAt` is never overwritten. It is the age of the problem and
 *    it feeds mean-time-to-remediate; recomputing it on every scan would make
 *    every finding look brand new and MTTR look perfect.
 *
 * 2. Human decisions outrank scanner output. ACCEPTED_RISK, FALSE_POSITIVE and
 *    SUPPRESSED are set by a person; a scanner seeing the finding again is not
 *    new information and must not silently reopen it. Those findings still get
 *    their `lastDetectedAt` advanced so "still present, still accepted" is
 *    distinguishable from "accepted and since fixed".
 */

/** Statuses a person set deliberately, which automation must not override. */
export const HUMAN_DECIDED_STATUSES: readonly FindingStatus[] = [
  "ACCEPTED_RISK",
  "FALSE_POSITIVE",
  "SUPPRESSED",
];

export function isHumanDecided(status: FindingStatus): boolean {
  return HUMAN_DECIDED_STATUSES.includes(status);
}

export interface ReconcileResult {
  finding: SecurityFinding;
  transition: FindingTransition;
}

/**
 * Merge an incoming (freshly parsed) finding with the stored one, if any.
 *
 * `incoming` carries the scanner's current view: severity, description, fix
 * version and location, all of which may legitimately have changed since the
 * last scan. `existing` carries history and human decisions. The merge takes
 * current facts from the scanner and history from the store.
 */
export function reconcileFinding(
  existing: SecurityFinding | undefined,
  incoming: SecurityFinding,
): ReconcileResult {
  if (!existing) {
    return {
      finding: {
        ...incoming,
        status: incoming.status === "SUPPRESSED" ? "SUPPRESSED" : "OPEN",
        firstDetectedAt: incoming.firstDetectedAt,
        lastDetectedAt: incoming.lastDetectedAt,
        // A scanner has no standing to record a human decision.
        statusReason: undefined,
        statusChangedAt: undefined,
        statusChangedBy: undefined,
      },
      transition: "NEW",
    };
  }

  // Keep the earliest first-seen timestamp even if scans arrive out of order
  // (CI retries, backfills, a delayed webhook).
  const firstDetectedAt =
    existing.firstDetectedAt < incoming.firstDetectedAt
      ? existing.firstDetectedAt
      : incoming.firstDetectedAt;

  const lastDetectedAt =
    existing.lastDetectedAt > incoming.lastDetectedAt
      ? existing.lastDetectedAt
      : incoming.lastDetectedAt;

  const merged: SecurityFinding = {
    // Scanner-current facts.
    ...incoming,
    // Stable identity and history.
    id: existing.id,
    fingerprint: existing.fingerprint,
    firstDetectedAt,
    lastDetectedAt,
    status: existing.status,
    resolvedAt: existing.resolvedAt,
    // A human decision outlives the scan that re-reported the finding. Omitting
    // these three lines silently erases every justification and its author on
    // the next scan.
    statusReason: existing.statusReason,
    statusChangedAt: existing.statusChangedAt,
    statusChangedBy: existing.statusChangedBy,
    metadata: { ...existing.metadata, ...incoming.metadata },
  };

  if (isHumanDecided(existing.status)) {
    // Seen again, but a human already ruled on it. Record that it is still
    // present; change nothing else.
    return { finding: merged, transition: "EXISTING" };
  }

  if (existing.status === "RESOLVED") {
    return {
      finding: {
        ...merged,
        status: "OPEN",
        resolvedAt: undefined,
        metadata: {
          ...merged.metadata,
          reopenedAt: incoming.lastDetectedAt,
          previouslyResolvedAt: existing.resolvedAt,
        },
      },
      transition: "REOPENED",
    };
  }

  return { finding: { ...merged, status: "OPEN" }, transition: "EXISTING" };
}

/**
 * Mark a finding resolved because the scan that should have found it did not.
 *
 * Returns the finding unchanged when it is not currently open — resolving an
 * accepted-risk finding would erase the acceptance.
 */
export function resolveFinding(
  finding: SecurityFinding,
  resolvedAt: string,
): SecurityFinding {
  if (finding.status !== "OPEN") return finding;
  return { ...finding, status: "RESOLVED", resolvedAt };
}

/**
 * Determine which stored findings a scan implicitly resolved.
 *
 * Scope matters: a Semgrep scan of `payment-service` says nothing about Trivy
 * findings, or about `user-service`. Auto-resolution is therefore limited to
 * findings sharing the scan's scanner AND repository, and only those the
 * current scan could plausibly have re-reported.
 */
export interface ResolutionScope {
  scanner: SecurityFinding["scanner"];
  repositoryName?: string;
  repositoryId?: string;
  environment?: string;
}

export function findResolvedFindings(
  storedFindings: readonly SecurityFinding[],
  seenFingerprints: ReadonlySet<string>,
  scope: ResolutionScope,
): SecurityFinding[] {
  return storedFindings.filter((finding) => {
    if (finding.status !== "OPEN") return false;
    if (finding.scanner !== scope.scanner) return false;
    if (seenFingerprints.has(finding.fingerprint)) return false;

    if (scope.repositoryId || finding.repositoryId) {
      if (finding.repositoryId !== scope.repositoryId) return false;
    } else if (finding.repositoryName !== scope.repositoryName) {
      return false;
    }

    if (scope.environment !== undefined || finding.environment !== undefined) {
      if (finding.environment !== scope.environment) return false;
    }

    return true;
  });
}

/** Valid manual status transitions, enforced at the service boundary. */
const ALLOWED_MANUAL_TRANSITIONS: Record<FindingStatus, FindingStatus[]> = {
  OPEN: ["ACCEPTED_RISK", "FALSE_POSITIVE", "SUPPRESSED", "RESOLVED"],
  RESOLVED: ["OPEN"],
  ACCEPTED_RISK: ["OPEN", "FALSE_POSITIVE", "RESOLVED"],
  FALSE_POSITIVE: ["OPEN", "ACCEPTED_RISK"],
  SUPPRESSED: ["OPEN", "ACCEPTED_RISK", "FALSE_POSITIVE"],
};

export function canTransition(
  from: FindingStatus,
  to: FindingStatus,
): boolean {
  return ALLOWED_MANUAL_TRANSITIONS[from]?.includes(to) ?? false;
}
