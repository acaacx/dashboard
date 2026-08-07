import { describe, expect, it } from "vitest";

import type { ScanRun } from "@/domain/security/scan-run";
import { emptyScanRunCounts } from "@/domain/security/scan-run";
import { InMemorySecurityFindingRepository } from "@/lib/security/repository/memory-security-finding-repository";
import {
  deriveScannerHealth,
  InMemoryScanRunRepository,
  SCANNER_STALE_AFTER_HOURS,
} from "@/lib/security/repository/scan-run-repository";
import { SecurityService } from "@/lib/security/services/security-service";

const NOW = new Date("2026-08-10T12:00:00.000Z");

function run(overrides: Partial<ScanRun> = {}): ScanRun {
  return {
    id: "run_1",
    scanner: "SEMGREP",
    repositoryName: "payment-service",
    status: "COMPLETED",
    startedAt: "2026-08-10T11:50:00.000Z",
    completedAt: "2026-08-10T11:52:00.000Z",
    findings: emptyScanRunCounts(),
    totalFindings: 0,
    ...overrides,
  };
}

describe("deriveScannerHealth", () => {
  it("reports HEALTHY for a recent completed run", () => {
    const [health] = deriveScannerHealth(
      ["SEMGREP"],
      new Map([["SEMGREP", run()]]),
      NOW,
    );

    expect(health.status).toBe("HEALTHY");
    expect(health.lastScanAt).toBe("2026-08-10T11:52:00.000Z");
    expect(health.lastRunStatus).toBe("COMPLETED");
  });

  // The distinction the whole design hinges on.
  it("reports NEVER_RUN rather than HEALTHY for a scanner with no runs", () => {
    const [health] = deriveScannerHealth(["TRIVY"], new Map(), NOW);

    expect(health.status).toBe("NEVER_RUN");
    expect(health.lastScanAt).toBeUndefined();
    expect(health.runCount).toBe(0);
  });

  it("distinguishes a clean scan from a scanner that never ran", () => {
    const clean = deriveScannerHealth(
      ["SEMGREP"],
      new Map([["SEMGREP", run({ totalFindings: 0 })]]),
      NOW,
    )[0];
    const missing = deriveScannerHealth(["TRIVY"], new Map(), NOW)[0];

    expect(clean.status).toBe("HEALTHY");
    expect(missing.status).toBe("NEVER_RUN");
  });

  it("reports FAILED with the safe error message", () => {
    const [health] = deriveScannerHealth(
      ["CHECKOV"],
      new Map([
        [
          "CHECKOV",
          run({ scanner: "CHECKOV", status: "FAILED", error: "Invalid SARIF document" }),
        ],
      ]),
      NOW,
    );

    expect(health.status).toBe("FAILED");
    expect(health.error).toBe("Invalid SARIF document");
  });

  it("reports WARNING once the last successful run goes stale", () => {
    const staleAt = new Date(
      NOW.getTime() - (SCANNER_STALE_AFTER_HOURS + 1) * 3_600_000,
    ).toISOString();

    const [health] = deriveScannerHealth(
      ["GITLEAKS"],
      new Map([
        ["GITLEAKS", run({ scanner: "GITLEAKS", completedAt: staleAt, startedAt: staleAt })],
      ]),
      NOW,
    );

    expect(health.status).toBe("WARNING");
  });

  it("treats a long-running scan as stuck, not healthy", () => {
    const longAgo = new Date(
      NOW.getTime() - (SCANNER_STALE_AFTER_HOURS + 5) * 3_600_000,
    ).toISOString();

    const [stuck] = deriveScannerHealth(
      ["TRIVY"],
      new Map([
        [
          "TRIVY",
          run({ scanner: "TRIVY", status: "RUNNING", startedAt: longAgo, completedAt: undefined }),
        ],
      ]),
      NOW,
    );
    expect(stuck.status).toBe("WARNING");

    const [inFlight] = deriveScannerHealth(
      ["TRIVY"],
      new Map([
        [
          "TRIVY",
          run({
            scanner: "TRIVY",
            status: "RUNNING",
            startedAt: "2026-08-10T11:59:00.000Z",
            completedAt: undefined,
          }),
        ],
      ]),
      NOW,
    );
    expect(inFlight.status).toBe("HEALTHY");
  });
});

describe("SecurityService.getScannerHealth", () => {
  it("lists configured scanners that have never reported", async () => {
    const service = new SecurityService(
      new InMemorySecurityFindingRepository(),
      new InMemoryScanRunRepository([run()]),
      ["SEMGREP", "TRIVY", "CHECKOV", "GITLEAKS"],
    );

    const health = await service.getScannerHealth(NOW);

    expect(health).toHaveLength(4);
    expect(health.find((entry) => entry.scanner === "SEMGREP")?.status).toBe(
      "HEALTHY",
    );
    expect(
      health
        .filter((entry) => entry.scanner !== "SEMGREP")
        .every((entry) => entry.status === "NEVER_RUN"),
    ).toBe(true);
  });

  it("includes a scanner that reported even if it is not in the configured list", async () => {
    const service = new SecurityService(
      new InMemorySecurityFindingRepository(),
      new InMemoryScanRunRepository([run({ scanner: "TRIVY" })]),
      [],
    );

    const health = await service.getScannerHealth(NOW);
    expect(health.map((entry) => entry.scanner)).toEqual(["TRIVY"]);
  });

  it("uses the most recent run per scanner", async () => {
    const service = new SecurityService(
      new InMemorySecurityFindingRepository(),
      new InMemoryScanRunRepository([
        run({ id: "old", startedAt: "2026-08-01T00:00:00.000Z", status: "FAILED" }),
        run({ id: "new", startedAt: "2026-08-10T11:50:00.000Z" }),
      ]),
      ["SEMGREP"],
    );

    const [health] = await service.getScannerHealth(NOW);
    expect(health.lastRunId).toBe("new");
    expect(health.status).toBe("HEALTHY");
    expect(health.runCount).toBe(2);
  });
});

describe("SecurityService.getRepositoryPipelines", () => {
  it("derives stages from observed runs rather than a fixed template", async () => {
    const service = new SecurityService(
      new InMemorySecurityFindingRepository(),
      new InMemoryScanRunRepository([
        run({ id: "r1", scanner: "SEMGREP", totalFindings: 0 }),
        run({ id: "r2", scanner: "TRIVY", totalFindings: 3 }),
        run({
          id: "r3",
          scanner: "GITLEAKS",
          repositoryName: "user-service",
          totalFindings: 0,
        }),
      ]),
      [],
    );

    const pipelines = await service.getRepositoryPipelines();

    const payment = pipelines.find(
      (entry) => entry.repositoryName === "payment-service",
    );
    const user = pipelines.find(
      (entry) => entry.repositoryName === "user-service",
    );

    // payment-service ran two scanners; user-service ran one. Neither gets a
    // phantom stage for a scanner it never ran.
    expect(payment?.stages.map((stage) => stage.scanner)).toEqual([
      "SEMGREP",
      "TRIVY",
    ]);
    expect(user?.stages.map((stage) => stage.scanner)).toEqual(["GITLEAKS"]);

    expect(payment?.stages[0].status).toBe("PASSED");
    expect(payment?.stages[1].status).toBe("FAILED");
    expect(payment?.stages[1].findings).toBe(3);
  });
});
