import { beforeEach, describe, expect, it } from "vitest";

import {
  InvalidStatusReasonError,
  InvalidStatusTransitionError,
} from "@/domain/security/errors";
import type { SecurityFinding } from "@/domain/security/finding";
import { InMemorySecurityFindingRepository } from "@/lib/security/repository/memory-security-finding-repository";
import { SecurityService } from "@/lib/security/services/security-service";

const NOW = new Date("2026-08-12T10:00:00.000Z");

function open(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: "fnd_1",
    fingerprint: "fp1",
    scanner: "SEMGREP",
    category: "SAST",
    severity: "HIGH",
    title: "SQL injection",
    repositoryName: "payment-service",
    status: "OPEN",
    firstDetectedAt: "2026-08-01T00:00:00.000Z",
    lastDetectedAt: "2026-08-10T00:00:00.000Z",
    ...overrides,
  };
}

let findings: InMemorySecurityFindingRepository;
let service: SecurityService;

beforeEach(async () => {
  findings = new InMemorySecurityFindingRepository();
  service = new SecurityService(findings);
  await findings.save(open());
});

describe("SecurityService.setFindingStatus", () => {
  it("records the reason and the moment of the decision", async () => {
    const updated = await service.setFindingStatus(
      "fnd_1",
      "ACCEPTED_RISK",
      "  Mitigated by the WAF rule shipped in PR 412.  ",
      { now: NOW },
    );

    expect(updated?.status).toBe("ACCEPTED_RISK");
    expect(updated?.statusReason).toBe(
      "Mitigated by the WAF rule shipped in PR 412.",
    );
    expect(updated?.statusChangedAt).toBe("2026-08-12T10:00:00.000Z");
  });

  it("requires a reason for every human-decided status", async () => {
    for (const status of [
      "ACCEPTED_RISK",
      "FALSE_POSITIVE",
      "SUPPRESSED",
    ] as const) {
      await expect(
        service.setFindingStatus("fnd_1", status, undefined, { now: NOW }),
      ).rejects.toBeInstanceOf(InvalidStatusReasonError);
    }
  });

  it("treats a whitespace-only reason as missing", async () => {
    await expect(
      service.setFindingStatus("fnd_1", "ACCEPTED_RISK", "   \n ", {
        now: NOW,
      }),
    ).rejects.toBeInstanceOf(InvalidStatusReasonError);
  });

  it("rejects a reason longer than the limit", async () => {
    await expect(
      service.setFindingStatus("fnd_1", "ACCEPTED_RISK", "x".repeat(501), {
        now: NOW,
      }),
    ).rejects.toBeInstanceOf(InvalidStatusReasonError);
  });

  it("clears a stale justification when a finding is reopened without one", async () => {
    await service.setFindingStatus("fnd_1", "FALSE_POSITIVE", "Test fixture.", {
      now: NOW,
    });

    const reopened = await service.setFindingStatus(
      "fnd_1",
      "OPEN",
      undefined,
      { now: new Date("2026-08-13T10:00:00.000Z") },
    );

    expect(reopened?.status).toBe("OPEN");
    expect(reopened?.statusReason).toBeUndefined();
    expect(reopened?.statusChangedAt).toBe("2026-08-13T10:00:00.000Z");
  });

  it("rejects a transition the lifecycle does not allow", async () => {
    await service.setFindingStatus("fnd_1", "FALSE_POSITIVE", "Test fixture.", {
      now: NOW,
    });

    await expect(
      service.setFindingStatus("fnd_1", "SUPPRESSED", "Because.", { now: NOW }),
    ).rejects.toBeInstanceOf(InvalidStatusTransitionError);
  });

  it("leaves a same-status call untouched and ignores its reason", async () => {
    await service.setFindingStatus("fnd_1", "ACCEPTED_RISK", "Original.", {
      now: NOW,
    });

    const again = await service.setFindingStatus(
      "fnd_1",
      "ACCEPTED_RISK",
      "Rewritten without a transition.",
      { now: new Date("2026-08-20T10:00:00.000Z") },
    );

    expect(again?.statusReason).toBe("Original.");
    expect(again?.statusChangedAt).toBe("2026-08-12T10:00:00.000Z");
  });

  it("returns null for an unknown id", async () => {
    expect(
      await service.setFindingStatus("fnd_missing", "ACCEPTED_RISK", "x", {
        now: NOW,
      }),
    ).toBeNull();
  });

  it("records who decided, and the next decision replaces the author", async () => {
    await service.setFindingStatus("fnd_1", "ACCEPTED_RISK", "Mitigated.", {
      changedBy: "approver@example.com",
      now: NOW,
    });

    expect((await findings.findById("fnd_1"))?.statusChangedBy).toBe(
      "approver@example.com",
    );

    const reopened = await service.setFindingStatus(
      "fnd_1",
      "OPEN",
      undefined,
      {
        changedBy: "second@example.com",
        now: NOW,
      },
    );

    // statusChangedAt and statusChangedBy describe the same event: the last
    // manual change. Reopening clears the justification but is itself a
    // decision, and it is the reopener's.
    expect(reopened?.statusChangedBy).toBe("second@example.com");
    expect(reopened?.statusReason).toBeUndefined();
  });

  it("records no author when none is supplied", async () => {
    const updated = await service.setFindingStatus(
      "fnd_1",
      "SUPPRESSED",
      "Known noise from the generated client.",
      { now: NOW },
    );

    expect(updated?.statusChangedBy).toBeUndefined();
  });
});
