"use server";

import { isFindingStatus, type FindingStatus } from "@/domain/security/enums";
import { isSecurityDomainError } from "@/domain/security/errors";
import { getSecurityService } from "@/lib/security/container";
import type { SetStatusResult } from "@/lib/security/status-change";

/**
 * Apply a human decision to a finding.
 *
 * This is a Server Action rather than a REST route on purpose. The application
 * has no user authentication, and the only credential it owns —
 * SECURITY_INGEST_TOKEN — belongs to CI and cannot be shipped to a browser. A
 * public endpoint that flips a CRITICAL finding to FALSE_POSITIVE is a direct
 * way to hide a real vulnerability, so no such endpoint exists. The honest
 * consequence is documented in the README: whoever can reach the dashboard can
 * change a finding's status.
 *
 * Failures come back as a value, never as a throw. An unexpected error's
 * message can contain an internal hostname or a payload fragment, so only
 * domain errors — which are safe by construction — pass their message through.
 */
export async function setFindingStatusAction(
  id: string,
  status: FindingStatus,
  reason: string | undefined,
): Promise<SetStatusResult> {
  if (!isFindingStatus(status)) {
    return {
      ok: false,
      code: "INVALID_STATUS_TRANSITION",
      message: "That is not a finding status.",
    };
  }

  // The UI withholds manual RESOLVED so mean-time-to-remediate cannot be
  // improved by assertion. Enforced here too: the select element is not a
  // security boundary.
  if (status === "RESOLVED") {
    return {
      ok: false,
      code: "INVALID_STATUS_TRANSITION",
      message: "A finding is resolved by a scan, not by hand.",
    };
  }

  try {
    const service = await getSecurityService();
    const finding = await service.setFindingStatus(id, status, reason);

    if (!finding) {
      return { ok: false, code: "NOT_FOUND", message: "Finding not found." };
    }

    return { ok: true, finding };
  } catch (error) {
    if (isSecurityDomainError(error)) {
      return { ok: false, code: error.code, message: error.message };
    }
    return {
      ok: false,
      code: "INTERNAL_ERROR",
      message: "The status change could not be applied.",
    };
  }
}
