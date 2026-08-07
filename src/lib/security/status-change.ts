import { FINDING_STATUSES, type FindingStatus } from "@/domain/security/enums";
import type { SecurityFinding } from "@/domain/security/finding";
import { canTransition } from "./lifecycle";

/**
 * The contract shared by the status-change Server Action and the components
 * that call it.
 *
 * Deliberately free of zod, `pg` and `"use server"`: a client component imports
 * it, and a component test imports it under jsdom without booting a server
 * runtime.
 */

/** Longest justification accepted. Long enough for a real risk acceptance. */
export const MAX_STATUS_REASON_LENGTH = 500;

/**
 * Statuses the UI offers, given where a finding is now.
 *
 * `canTransition` permits OPEN -> RESOLVED. This deliberately does not: RESOLVED
 * means a scan stopped seeing the finding, and letting a person assert it by
 * hand turns mean-time-to-remediate into a number anyone can improve without
 * fixing anything. The service still permits it — the restriction is policy at
 * this boundary, and the Server Action enforces it so a crafted request cannot
 * route around the select element.
 */
export function selectableTransitions(from: FindingStatus): FindingStatus[] {
  return FINDING_STATUSES.filter(
    (to) => to !== from && to !== "RESOLVED" && canTransition(from, to),
  );
}

/**
 * Result of a status change. The action returns this rather than throwing, so
 * an unexpected failure cannot deliver a stack trace or an internal path to the
 * browser.
 */
export type SetStatusResult =
  | { ok: true; finding: SecurityFinding }
  | { ok: false; code: string; message: string };

export type SetFindingStatusAction = (
  id: string,
  status: FindingStatus,
  reason: string | undefined,
) => Promise<SetStatusResult>;
