import { describe, expect, it } from "vitest";

import type { SecurityFinding } from "@/domain/security/finding";
import {
  canTransition,
  findResolvedFindings,
  isHumanDecided,
  reconcileFinding,
  resolveFinding,
} from "@/lib/security/lifecycle";

function finding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: "fnd_1",
    fingerprint: "fp1",
    scanner: "SEMGREP",
    category: "SAST",
    severity: "HIGH",
    title: "SQL injection",
    repositoryName: "payment-service",
    environment: "production",
    status: "OPEN",
    firstDetectedAt: "2026-07-01T00:00:00.000Z",
    lastDetectedAt: "2026-07-01T00:00:00.000Z",
    ...overrides,
  };
}

describe("reconcileFinding", () => {
  it("marks an unseen finding NEW and stores it OPEN", () => {
    const incoming = finding();
    const { finding: stored, transition } = reconcileFinding(undefined, incoming);

    expect(transition).toBe("NEW");
    expect(stored.status).toBe("OPEN");
    expect(stored.firstDetectedAt).toBe(incoming.firstDetectedAt);
  });

  it("preserves firstDetectedAt across rescans", () => {
    const existing = finding({
      firstDetectedAt: "2026-06-01T00:00:00.000Z",
      lastDetectedAt: "2026-06-15T00:00:00.000Z",
    });
    const incoming = finding({
      firstDetectedAt: "2026-08-01T00:00:00.000Z",
      lastDetectedAt: "2026-08-01T00:00:00.000Z",
    });

    const { finding: merged, transition } = reconcileFinding(existing, incoming);

    expect(transition).toBe("EXISTING");
    // The age of the problem must not reset on every pipeline run.
    expect(merged.firstDetectedAt).toBe("2026-06-01T00:00:00.000Z");
    expect(merged.lastDetectedAt).toBe("2026-08-01T00:00:00.000Z");
  });

  it("keeps the earliest first-seen when scans arrive out of order", () => {
    const existing = finding({
      firstDetectedAt: "2026-07-10T00:00:00.000Z",
      lastDetectedAt: "2026-07-10T00:00:00.000Z",
    });
    const backfill = finding({
      firstDetectedAt: "2026-05-01T00:00:00.000Z",
      lastDetectedAt: "2026-05-01T00:00:00.000Z",
    });

    const { finding: merged } = reconcileFinding(existing, backfill);
    expect(merged.firstDetectedAt).toBe("2026-05-01T00:00:00.000Z");
    // A late-arriving old scan must not rewind "last detected".
    expect(merged.lastDetectedAt).toBe("2026-07-10T00:00:00.000Z");
  });

  it("takes current facts from the scanner but identity from the store", () => {
    const existing = finding({ id: "fnd_stored", severity: "MEDIUM" });
    const incoming = finding({
      id: "fnd_recomputed",
      severity: "CRITICAL",
      fixedVersion: "1.2.3",
    });

    const { finding: merged } = reconcileFinding(existing, incoming);

    expect(merged.id).toBe("fnd_stored");
    // A re-rated CVE is the same finding at a new severity.
    expect(merged.severity).toBe("CRITICAL");
    expect(merged.fixedVersion).toBe("1.2.3");
  });

  it("reopens a resolved finding and clears resolvedAt", () => {
    const existing = finding({
      status: "RESOLVED",
      resolvedAt: "2026-07-20T00:00:00.000Z",
    });
    const incoming = finding({ lastDetectedAt: "2026-08-01T00:00:00.000Z" });

    const { finding: merged, transition } = reconcileFinding(existing, incoming);

    expect(transition).toBe("REOPENED");
    expect(merged.status).toBe("OPEN");
    expect(merged.resolvedAt).toBeUndefined();
    expect(merged.metadata?.previouslyResolvedAt).toBe("2026-07-20T00:00:00.000Z");
    expect(merged.metadata?.reopenedAt).toBe("2026-08-01T00:00:00.000Z");
  });

  it.each(["ACCEPTED_RISK", "FALSE_POSITIVE", "SUPPRESSED"] as const)(
    "does not let a rescan override the human decision %s",
    (status) => {
      const existing = finding({ status });
      const incoming = finding({ lastDetectedAt: "2026-08-01T00:00:00.000Z" });

      const { finding: merged, transition } = reconcileFinding(existing, incoming);

      expect(transition).toBe("EXISTING");
      expect(merged.status).toBe(status);
      // Still updated, so "accepted and still present" is distinguishable from
      // "accepted and since fixed".
      expect(merged.lastDetectedAt).toBe("2026-08-01T00:00:00.000Z");
    },
  );

  it("respects a SUPPRESSED marker on a brand new finding", () => {
    const { finding: stored } = reconcileFinding(
      undefined,
      finding({ status: "SUPPRESSED" }),
    );
    expect(stored.status).toBe("SUPPRESSED");
  });
});

describe("resolveFinding", () => {
  it("resolves an open finding", () => {
    const resolved = resolveFinding(finding(), "2026-08-01T00:00:00.000Z");
    expect(resolved.status).toBe("RESOLVED");
    expect(resolved.resolvedAt).toBe("2026-08-01T00:00:00.000Z");
  });

  it("leaves non-open findings alone", () => {
    const accepted = finding({ status: "ACCEPTED_RISK" });
    expect(resolveFinding(accepted, "2026-08-01T00:00:00.000Z")).toBe(accepted);
  });
});

describe("findResolvedFindings", () => {
  const stored: SecurityFinding[] = [
    finding({ id: "a", fingerprint: "fp_a" }),
    finding({ id: "b", fingerprint: "fp_b" }),
    finding({ id: "c", fingerprint: "fp_c", scanner: "TRIVY" }),
    finding({ id: "d", fingerprint: "fp_d", repositoryName: "user-service" }),
    finding({ id: "e", fingerprint: "fp_e", status: "ACCEPTED_RISK" }),
  ];

  const scope = {
    scanner: "SEMGREP" as const,
    repositoryName: "payment-service",
    environment: "production",
  };

  it("resolves only what this scan should have re-reported", () => {
    const resolved = findResolvedFindings(stored, new Set(["fp_a"]), scope);

    // b: same scanner + repo, not seen -> resolved.
    expect(resolved.map((entry) => entry.id)).toEqual(["b"]);
  });

  it("never resolves another scanner's findings", () => {
    const resolved = findResolvedFindings(stored, new Set(), scope);
    expect(resolved.some((entry) => entry.scanner === "TRIVY")).toBe(false);
  });

  it("never resolves another repository's findings", () => {
    const resolved = findResolvedFindings(stored, new Set(), scope);
    expect(resolved.some((entry) => entry.repositoryName === "user-service")).toBe(
      false,
    );
  });

  it("never auto-resolves a human-decided finding", () => {
    const resolved = findResolvedFindings(stored, new Set(), scope);
    expect(resolved.some((entry) => entry.status === "ACCEPTED_RISK")).toBe(false);
  });

  it("scopes by repositoryId when the scan supplies one", () => {
    const withIds: SecurityFinding[] = [
      finding({ id: "x", fingerprint: "fp_x", repositoryId: "repo_1" }),
      finding({ id: "y", fingerprint: "fp_y", repositoryId: "repo_2" }),
    ];

    const resolved = findResolvedFindings(withIds, new Set(), {
      scanner: "SEMGREP",
      repositoryId: "repo_1",
      environment: "production",
    });

    expect(resolved.map((entry) => entry.id)).toEqual(["x"]);
  });
});

describe("canTransition", () => {
  it("allows the documented manual transitions", () => {
    expect(canTransition("OPEN", "ACCEPTED_RISK")).toBe(true);
    expect(canTransition("OPEN", "FALSE_POSITIVE")).toBe(true);
    expect(canTransition("ACCEPTED_RISK", "OPEN")).toBe(true);
    expect(canTransition("RESOLVED", "OPEN")).toBe(true);
  });

  it("rejects nonsensical ones", () => {
    expect(canTransition("RESOLVED", "ACCEPTED_RISK")).toBe(false);
    expect(canTransition("FALSE_POSITIVE", "RESOLVED")).toBe(false);
  });
});

describe("isHumanDecided", () => {
  it("identifies statuses automation must not override", () => {
    expect(isHumanDecided("ACCEPTED_RISK")).toBe(true);
    expect(isHumanDecided("FALSE_POSITIVE")).toBe(true);
    expect(isHumanDecided("SUPPRESSED")).toBe(true);
    expect(isHumanDecided("OPEN")).toBe(false);
    expect(isHumanDecided("RESOLVED")).toBe(false);
  });
});
