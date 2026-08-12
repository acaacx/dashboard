import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { createDefaultAdapterRegistry } from "@/lib/security/adapters";
import { PostgresSecurityFindingRepository } from "@/lib/security/repository/postgres-security-finding-repository";
import { PostgresScanRunRepository } from "@/lib/security/repository/postgres-scan-run-repository";
import { ScanIngestionService } from "@/lib/security/services/scan-ingestion-service";
import { SecurityService } from "@/lib/security/services/security-service";
import { loadFixture } from "../helpers/fixtures";
import {
  createScopedTestPool,
  prepareSchema,
  TEST_DATABASE_URL,
} from "../helpers/postgres";

/**
 * End-to-end ingestion over real SQL.
 *
 * The repository contract proves the store behaves; this proves the pipeline
 * built on top of it — deduplication, lifecycle transitions, auto-resolution
 * and scan-run recording — behaves the same when the state lives in Postgres
 * across separate connections rather than in a process-local Map.
 *
 * Skipped unless TEST_DATABASE_URL is set.
 */

const semgrepJson = loadFixture("semgrep/result.json");

const SCHEMA = "test_ingestion";

if (!TEST_DATABASE_URL) {
  describe.skip("scan ingestion on postgres", () => {
    it("skipped: TEST_DATABASE_URL is not set", () => {});
  });
} else {
  // Dedicated schema: this file truncates freely and must not race the
  // repository contract suite running in a parallel worker.
  const pool = createScopedTestPool(SCHEMA);

  const findings = new PostgresSecurityFindingRepository(pool);
  const runs = new PostgresScanRunRepository(pool);
  const registry = createDefaultAdapterRegistry();
  const ingestion = new ScanIngestionService(registry, findings, runs);
  const security = new SecurityService(
    findings,
    runs,
    registry.supportedScanners(),
  );

  const request = {
    scanner: "SEMGREP" as const,
    repositoryId: "repo_payment",
    repositoryName: "payment-service",
    branch: "main",
    environment: "production",
    results: semgrepJson,
  };

  beforeAll(async () => {
    await prepareSchema(pool, SCHEMA);
  });

  beforeEach(async () => {
    await pool.query("TRUNCATE security_findings CASCADE");
    await pool.query("TRUNCATE scan_runs");
  });

  afterAll(async () => {
    await pool.end();
  });

  describe("scan ingestion on postgres", () => {
    it("persists findings and a completed scan run", async () => {
      const result = await ingestion.ingest({
        ...request,
        scannedAt: "2026-08-01T10:00:00.000Z",
      });

      expect(result.summary.created).toBe(2);
      expect(result.scanRun.status).toBe("COMPLETED");

      expect(await findings.count()).toBe(2);

      const storedRuns = await runs.findAll();
      expect(storedRuns).toHaveLength(1);
      // The scan timestamp and the ingestion timestamp stay distinct.
      expect(storedRuns[0].startedAt).toBe("2026-08-01T10:00:00.000Z");
      expect(storedRuns[0].ingestedAt).toBeDefined();
    });

    it("does not duplicate when the pipeline runs again", async () => {
      await ingestion.ingest({ ...request, scannedAt: "2026-08-01T10:00:00.000Z" });
      const second = await ingestion.ingest({
        ...request,
        scannedAt: "2026-08-02T10:00:00.000Z",
      });

      expect(second.summary.created).toBe(0);
      expect(second.summary.updated).toBe(2);
      expect(await findings.count()).toBe(2);

      const page = await findings.findAll();
      page.items.forEach((finding) => {
        // History preserved, currency advanced.
        expect(finding.firstDetectedAt).toBe("2026-08-01T10:00:00.000Z");
        expect(finding.lastDetectedAt).toBe("2026-08-02T10:00:00.000Z");
      });
    });

    it("auto-resolves and then reopens across the SQL boundary", async () => {
      await ingestion.ingest({ ...request, scannedAt: "2026-08-01T10:00:00.000Z" });

      const trimmed = structuredClone(semgrepJson) as { results: unknown[] };
      trimmed.results = [trimmed.results[0]];

      const second = await ingestion.ingest({
        ...request,
        results: trimmed,
        scannedAt: "2026-08-06T10:00:00.000Z",
      });
      expect(second.summary.resolved).toBe(1);
      expect((await findings.findAll({ status: ["RESOLVED"] })).total).toBe(1);

      const third = await ingestion.ingest({
        ...request,
        scannedAt: "2026-08-10T10:00:00.000Z",
      });
      expect(third.summary.reopened).toBe(1);
      expect((await findings.findAll({ status: ["OPEN"] })).total).toBe(2);
      expect((await findings.findAll({ status: ["RESOLVED"] })).total).toBe(0);
    });

    it("never auto-resolves a finding a human accepted", async () => {
      await ingestion.ingest({ ...request, scannedAt: "2026-08-01T10:00:00.000Z" });

      const page = await findings.findAll({ status: ["OPEN"] });
      const target = page.items[0];
      await security.setFindingStatus(
        target.id,
        "ACCEPTED_RISK",
        "Accepted for the duration of the migration.",
      );

      await ingestion.ingest({
        ...request,
        results: { results: [] },
        scannedAt: "2026-08-07T10:00:00.000Z",
      });

      const stored = await findings.findById(target.id);
      expect(stored?.status).toBe("ACCEPTED_RISK");
      expect(stored?.resolvedAt).toBeUndefined();
    });

    it("derives scanner health from persisted runs", async () => {
      await ingestion.ingest({
        ...request,
        scannedAt: "2026-08-10T11:52:00.000Z",
      });

      const health = await security.getScannerHealth(
        new Date("2026-08-10T12:00:00.000Z"),
      );

      const semgrep = health.find((entry) => entry.scanner === "SEMGREP");
      const trivy = health.find((entry) => entry.scanner === "TRIVY");

      expect(semgrep?.status).toBe("HEALTHY");
      // Configured but never reported — still distinguishable after a restart.
      expect(trivy?.status).toBe("NEVER_RUN");
    });

    it("records a FAILED run for an unparseable payload", async () => {
      await ingestion
        .ingest({
          scanner: "SEMGREP",
          repositoryName: "payment-service",
          results: { version: "1.0.0", runs: [], $schema: "sarif" },
        })
        .catch(() => undefined);

      const [failed] = await runs.findAll();
      expect(failed.status).toBe("FAILED");
      expect(failed.error).toContain("SARIF");
    });
  });
}
