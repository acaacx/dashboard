import { describe, expect, it } from "vitest";

import type { SecurityFinding } from "@/domain/security/finding";
import { InMemorySecurityFindingRepository } from "@/lib/security/repository/memory-security-finding-repository";
import { InMemoryScanRunRepository } from "@/lib/security/repository/scan-run-repository";
import {
  SecurityService,
  timeframeCutoff,
} from "@/lib/security/services/security-service";

const NOW = new Date("2026-08-10T12:00:00.000Z");

function finding(overrides: Partial<SecurityFinding>): SecurityFinding {
  return {
    id: `fnd_${overrides.fingerprint ?? "x"}`,
    fingerprint: String(overrides.fingerprint ?? "x"),
    scanner: "SEMGREP",
    category: "SAST",
    severity: "MEDIUM",
    title: "finding",
    repositoryName: "payment-service",
    environment: "production",
    status: "OPEN",
    firstDetectedAt: "2026-08-01T00:00:00.000Z",
    lastDetectedAt: "2026-08-10T00:00:00.000Z",
    ...overrides,
  };
}

const dataset: SecurityFinding[] = [
  finding({ fingerprint: "a", severity: "CRITICAL" }),
  finding({ fingerprint: "b", severity: "HIGH", scanner: "TRIVY", category: "SCA" }),
  finding({ fingerprint: "c", severity: "MEDIUM", repositoryName: "user-service" }),
  finding({
    fingerprint: "d",
    severity: "CRITICAL",
    status: "RESOLVED",
    firstDetectedAt: "2026-08-01T00:00:00.000Z",
    resolvedAt: "2026-08-03T00:00:00.000Z",
  }),
  finding({ fingerprint: "e", severity: "HIGH", status: "ACCEPTED_RISK" }),
  finding({ fingerprint: "f", severity: "LOW", status: "FALSE_POSITIVE" }),
  finding({
    fingerprint: "g",
    severity: "HIGH",
    environment: "staging",
    firstDetectedAt: "2026-06-01T00:00:00.000Z",
    lastDetectedAt: "2026-06-02T00:00:00.000Z",
  }),
];

function service(findings = dataset) {
  const repository = new InMemorySecurityFindingRepository(findings);
  return new SecurityService(repository, new InMemoryScanRunRepository(), []);
}

describe("statistics", () => {
  it("counts lifecycle states separately", async () => {
    const stats = await service().getStatistics({}, "all", NOW);

    expect(stats.total).toBe(7);
    expect(stats.totalOpen).toBe(4);
    expect(stats.totalResolved).toBe(1);
    expect(stats.totalAcceptedRisk).toBe(1);
    expect(stats.totalFalsePositive).toBe(1);
  });

  // Section 16 of the brief: resolved findings must never inflate "open".
  it("breaks down open findings only, never resolved ones", async () => {
    const stats = await service().getStatistics({}, "all", NOW);

    expect(stats.bySeverity.CRITICAL).toBe(1); // the resolved CRITICAL is excluded
    expect(stats.bySeverity.HIGH).toBe(2); // accepted-risk HIGH excluded
    expect(stats.bySeverity.MEDIUM).toBe(1);
    expect(stats.bySeverity.LOW).toBe(0); // the only LOW is a false positive

    const openTotal = Object.values(stats.bySeverity).reduce(
      (sum, value) => sum + value,
      0,
    );
    expect(openTotal).toBe(stats.totalOpen);
  });

  it("groups by scanner, category, repository and environment", async () => {
    const stats = await service().getStatistics({}, "all", NOW);

    expect(stats.byScanner).toEqual({ SEMGREP: 3, TRIVY: 1 });
    expect(stats.byCategory).toEqual({ SAST: 3, SCA: 1 });
    expect(stats.byRepository).toEqual({
      "payment-service": 3,
      "user-service": 1,
    });
    expect(stats.byEnvironment).toEqual({ production: 3, staging: 1 });
  });

  it("computes mean time to remediate from lifecycle timestamps", async () => {
    const stats = await service().getStatistics({}, "all", NOW);
    // Resolved 'd': detected 08-01, resolved 08-03 -> 48 hours.
    expect(stats.meanTimeToRemediateHours).toBe(48);
  });

  it("leaves MTTR undefined rather than reporting zero when nothing resolved", async () => {
    const stats = await service([finding({ fingerprint: "solo" })]).getStatistics(
      {},
      "all",
      NOW,
    );
    expect(stats.meanTimeToRemediateHours).toBeUndefined();
  });

  it("narrows the population and the counters together for a timeframe", async () => {
    const stats = await service().getStatistics({}, "7d", NOW);

    // 'g' was last detected in June, so it drops out of a 7-day view entirely.
    expect(stats.byEnvironment.staging).toBeUndefined();
    expect(stats.totalOpen).toBe(3);
  });

  it("applies filters to statistics as well as to lists", async () => {
    const stats = await service().getStatistics(
      { repository: ["payment-service"] },
      "all",
      NOW,
    );

    expect(stats.byRepository).toEqual({ "payment-service": 3 });
    expect(stats.totalOpen).toBe(3);
  });
});

describe("filtering and search", () => {
  it("filters by each supported dimension", async () => {
    const svc = service();

    expect((await svc.getFindings({ severity: ["CRITICAL"] })).total).toBe(2);
    expect((await svc.getFindings({ scanner: ["TRIVY"] })).total).toBe(1);
    expect((await svc.getFindings({ category: ["SCA"] })).total).toBe(1);
    expect((await svc.getFindings({ status: ["ACCEPTED_RISK"] })).total).toBe(1);
    expect((await svc.getFindings({ repository: ["user-service"] })).total).toBe(1);
    expect((await svc.getFindings({ environment: ["staging"] })).total).toBe(1);
  });

  it("combines filters with AND", async () => {
    const result = await service().getFindings({
      severity: ["HIGH"],
      status: ["OPEN"],
      environment: ["production"],
    });
    expect(result.total).toBe(1);
  });

  it("searches across title, CVE, rule id, file, resource and package", async () => {
    const svc = service([
      finding({ fingerprint: "s1", title: "SQL injection in checkout" }),
      finding({ fingerprint: "s2", cve: "CVE-2026-3456" }),
      finding({ fingerprint: "s3", ruleId: "CKV_AZURE_59" }),
      finding({ fingerprint: "s4", file: "src/payments/repository.py" }),
      finding({ fingerprint: "s5", resource: "azurerm_storage_account.assets" }),
      finding({ fingerprint: "s6", packageName: "lodash" }),
      finding({ fingerprint: "s7", cwe: "CWE-89" }),
    ]);

    expect((await svc.getFindings({ search: "sql injection" })).total).toBe(1);
    expect((await svc.getFindings({ search: "cve-2026-3456" })).total).toBe(1);
    expect((await svc.getFindings({ search: "CKV_AZURE" })).total).toBe(1);
    expect((await svc.getFindings({ search: "repository.py" })).total).toBe(1);
    expect((await svc.getFindings({ search: "storage_account" })).total).toBe(1);
    expect((await svc.getFindings({ search: "lodash" })).total).toBe(1);
    expect((await svc.getFindings({ search: "CWE-89" })).total).toBe(1);
    expect((await svc.getFindings({ search: "nothing-matches" })).total).toBe(0);
  });

  it("sorts by severity with the worst first by default", async () => {
    const result = await service().getFindings({ status: ["OPEN"] });
    expect(result.items[0].severity).toBe("CRITICAL");
  });

  it("paginates without losing or repeating rows", async () => {
    const many = Array.from({ length: 25 }, (_, index) =>
      finding({ fingerprint: `p${index}` }),
    );
    const svc = service(many);

    const first = await svc.getFindings({ pageSize: 10, page: 1 });
    const second = await svc.getFindings({ pageSize: 10, page: 2 });
    const third = await svc.getFindings({ pageSize: 10, page: 3 });

    expect(first.items).toHaveLength(10);
    expect(third.items).toHaveLength(5);
    expect(first.totalPages).toBe(3);

    const ids = [...first.items, ...second.items, ...third.items].map(
      (entry) => entry.id,
    );
    expect(new Set(ids).size).toBe(25);
  });

  it("clamps an out-of-range page instead of returning an empty table", async () => {
    const result = await service().getFindings({ page: 99, pageSize: 10 });
    expect(result.page).toBe(1);
    expect(result.items.length).toBeGreaterThan(0);
  });
});

describe("trend", () => {
  it("reports open backlog, new and resolved per day", async () => {
    const svc = service([
      finding({
        fingerprint: "t1",
        firstDetectedAt: "2026-08-08T00:00:00.000Z",
        lastDetectedAt: "2026-08-10T00:00:00.000Z",
      }),
      finding({
        fingerprint: "t2",
        firstDetectedAt: "2026-08-08T00:00:00.000Z",
        status: "RESOLVED",
        resolvedAt: "2026-08-09T00:00:00.000Z",
      }),
    ]);

    const points = await svc.getTrend(30, {}, NOW);
    const byDate = new Map(points.map((point) => [point.date, point]));

    expect(byDate.get("2026-08-08")?.new).toBe(2);
    expect(byDate.get("2026-08-08")?.open).toBe(2);
    expect(byDate.get("2026-08-09")?.resolved).toBe(1);
    // After one is resolved, the backlog drops to one.
    expect(byDate.get("2026-08-09")?.open).toBe(1);
  });

  it("returns the requested number of days", async () => {
    expect(await service().getTrend(14, {}, NOW)).toHaveLength(14);
    expect(await service().getTrend(1, {}, NOW)).toHaveLength(1);
  });
});

describe("timeframeCutoff", () => {
  it("computes cutoffs relative to now", () => {
    expect(timeframeCutoff("24h", NOW)).toBe("2026-08-09T12:00:00.000Z");
    expect(timeframeCutoff("7d", NOW)).toBe("2026-08-03T12:00:00.000Z");
    expect(timeframeCutoff("30d", NOW)).toBe("2026-07-11T12:00:00.000Z");
    expect(timeframeCutoff("all", NOW)).toBeUndefined();
  });
});

describe("repository summaries", () => {
  it("rolls up open findings per repository", async () => {
    const summaries = await service().getRepositorySummaries();
    const payment = summaries.find(
      (entry) => entry.repositoryName === "payment-service",
    );

    expect(payment?.openFindings).toBe(3);
    expect(payment?.bySeverity.CRITICAL).toBe(1);
    expect(summaries[0].openFindings).toBeGreaterThanOrEqual(
      summaries[summaries.length - 1].openFindings,
    );
  });
});
