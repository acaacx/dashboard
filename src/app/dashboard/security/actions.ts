"use server";

import { isAuthDomainError } from "@/domain/auth/errors";
import { isFindingStatus, type FindingStatus } from "@/domain/security/enums";
import { isSecurityDomainError } from "@/domain/security/errors";
import { requireApprover } from "@/lib/auth/guards";
import { getSecurityService } from "@/lib/security/container";
import type { SetStatusResult } from "@/lib/security/status-change";

/**
 * Apply a human decision to a finding.
 *
 * A Server Action rather than a REST route: an endpoint that flips a CRITICAL
 * finding to FALSE_POSITIVE is a direct way to hide a real vulnerability, and
 * the only credential CI holds — SECURITY_INGEST_TOKEN — must never reach a
 * browser.
 *
 * `requireApprover()` runs here regardless of what the drawer rendered. The
 * drawer's `canDecide` only chooses between an enabled and a locked control; a
 * select element is not a security boundary, which is the same reason the
 * manual-RESOLVED ban is enforced below rather than only hidden in the UI.
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
    const user = await requireApprover();

    const service = await getSecurityService();
    const finding = await service.setFindingStatus(id, status, reason, {
      changedBy: user.email,
    });

    if (!finding) {
      return { ok: false, code: "NOT_FOUND", message: "Finding not found." };
    }

    return { ok: true, finding };
  } catch (error) {
    // UNAUTHENTICATED and FORBIDDEN arrive here from requireApprover. Both
    // messages are written to be safe to show a browser.
    if (isAuthDomainError(error) || isSecurityDomainError(error)) {
      return { ok: false, code: error.code, message: error.message };
    }
    return {
      ok: false,
      code: "INTERNAL_ERROR",
      message: "The status change could not be applied.",
    };
  }
}
