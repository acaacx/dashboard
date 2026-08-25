import { describe, expect, it } from "vitest";

import { createDefaultAdapterRegistry } from "@/lib/security/adapters";
import { seedMockData } from "@/lib/security/mock/seed-mock-data";
import { InMemorySecurityFindingRepository } from "@/lib/security/repository/memory-security-finding-repository";
import { InMemoryScanRunRepository } from "@/lib/security/repository/scan-run-repository";
import { ScanIngestionService } from "@/lib/security/services/scan-ingestion-service";
import { SecurityService } from "@/lib/security/services/security-service";

/**
 * The seeded dashboard's headline numbers are a documented contract: README
 * and CLAUDE.md both quote 23 open / 3 critical / 7 high / 13 medium / 0 low,
 * and screenshots and demos are written against them.
 *
 * Nothing asserted them until this file. The payloads are replayed through the
 * real adapters, so an unrelated change to a fixture, a severity mapping or the
 * fingerprint inputs moves these counts silently — the dashboard still renders,
 * it just stops matching what the docs promise.
 */

const NOW = new Date("2026-08-19T12:00:00.000Z");

async function seed() {
  const findings = new InMemorySecurityFindingRepository();
  const runs = new InMemoryScanRunRepository();
  const ingestion = new ScanIngestionService(
    createDefaultAdapterRegistry(),
    findings,
    runs,
  );
  const security = new SecurityService(findings, runs, []);

  const result = await seedMockData(ingestion, security, NOW);
  return { security, result };
}

describe("seedMockData headline numbers", () => {
  it("hits the documented open and severity counts", async () => {
    const { security } = await seed();
    const stats = await security.getStatistics({}, "all", NOW);

    expect(stats.totalOpen).toBe(23);
    expect(stats.bySeverity.CRITICAL).toBe(3);
    expect(stats.bySeverity.HIGH).toBe(7);
    expect(stats.bySeverity.MEDIUM).toBe(13);
    expect(stats.bySeverity.LOW).toBe(0);
  });

  it("keeps the severity breakdown summing to the open total", async () => {
    const { security } = await seed();
    const stats = await security.getStatistics({}, "all", NOW);

    const summed = Object.values(stats.bySeverity).reduce(
      (total, count) => total + count,
      0,
    );
    expect(summed).toBe(stats.totalOpen);
  });

  it("accepts exactly one risk, so the Accepted Risk card is never a zero", async () => {
    const { security } = await seed();
    const stats = await security.getStatistics({}, "all", NOW);

    expect(stats.totalAcceptedRisk).toBe(1);
  });

  it("resolves the stale findings the second pass drops", async () => {
    const { security } = await seed();
    const stats = await security.getStatistics({}, "all", NOW);

    // The T-21d pass carries findings the later passes omit. Auto-resolution is
    // what gives the trend chart and MTTR something real to compute from, so a
    // zero here means the three-pass seed has collapsed into a flat snapshot.
    expect(stats.totalResolved).toBeGreaterThan(0);
  });

  it("ingests three passes over every mock scan", async () => {
    const { security, result } = await seed();
    const stats = await security.getStatistics({}, "all", NOW);

    // Eight scan definitions replayed at T-21d, T-10d and now.
    expect(result.scansIngested).toBe(24);

    // Every finding the store holds is in exactly one lifecycle state, so the
    // states have to add back up to the row count the seeder reported.
    expect(result.findingsStored).toBe(stats.total);
    expect(
      stats.totalOpen +
        stats.totalResolved +
        stats.totalAcceptedRisk +
        stats.totalFalsePositive,
    ).toBe(stats.total);
  });
});
