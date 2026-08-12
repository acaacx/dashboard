import type { FindingStatus } from "./enums";

/**
 * One human decision about a finding's status: who moved it, from what, to
 * what, and why. Append-only — nothing updates or deletes a recorded decision.
 *
 * Scanner-driven transitions (auto-resolve, reopen-by-scan) never appear here:
 * no person made them, and an attributed audit trail must not invent authors.
 */
export interface FindingDecision {
  id: string;
  findingId: string;
  fromStatus: FindingStatus;
  toStatus: FindingStatus;
  /** Nullable only because reopening to OPEN permits an absent justification. */
  reason?: string;
  /**
   * Email snapshot of the decider. Text, not a foreign key — same reasoning
   * as `statusChangedBy` on the finding itself.
   */
  decidedBy: string;
  /** ISO-8601 UTC instant. */
  decidedAt: string;
}
