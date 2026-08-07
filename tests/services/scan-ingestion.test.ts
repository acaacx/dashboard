import { beforeEach, describe, expect, it } from "vitest";

import { InvalidSarifError } from "@/domain/security/errors";
import { createDefaultAdapterRegistry } from "@/lib/security/adapters";
import { InMemorySecurityFindingRepository } from "@/lib/security/repository/memory-security-finding-repository";
import { InMemoryScanRunRepository } from "@/lib/security/repository/scan-run-repository";
import {
  dedupeByFingerprint,
  ScanIngestionService,
} from "@/lib/security/services/scan-ingestion-service";
import {
  getSecurityEventCounters,
  resetSecurityEventCounters,
} from "@/lib/security/observability";
import { loadFixture } from "../helpers/fixtures";

const semgrepJson = loadFixture("semgrep/result.json");
const trivyJson = loadFixture("trivy/result.json");

function build() {
  const findings = new InMemorySecurityFindingRepository();
  const runs = new InMemoryScanRunRepository();
  const registry = createDefaultAdapterRegistry();
  const ingestion = new ScanIngestionService(registry, findings, runs);
  return { findings, runs, ingestion };
}

const baseRequest = {
  scanner: "SEMGREP" as const,
  repositoryId: "repo_payment",
  repositoryName: "payment-service",
  branch: "main",
  environment: "production",
  results: semgrepJson,
};

describe("ScanIngestionService.ingest", () => {
  beforeEach(() => {
    resetSecurityEventCounters();
  });

  it("stores normalized findings and records a completed scan run", async () => {
    const { ingestion, findings } = build();

    const result = await ingestion.ingest({
      ...baseRequest,
      scannedAt: "2026-08-01T10:00:00.000Z",
    });

    expect(result.summary.created).toBe(2);
    expect(result.scanRun.status).toBe("COMPLETED");
    expect(result.scanRun.totalFindings).toBe(2);
    expect(result.scanRun.findings.critical).toBe(1);
    expect(result.scanRun.findings.medium).toBe(1);
    expect(result.scanRun.durationSeconds).toBeGreaterThanOrEqual(0);

    const page = await findings.findAll();
    expect(page.total).toBe(2);
    expect(page.items.every((finding) => finding.status === "OPEN")).toBe(true);
  });

  // The core requirement: running the pipeline again must not duplicate.
  it("does not duplicate findings when the same scan runs twice", async () => {
    const { ingestion, findings } = build();

    await ingestion.ingest({ ...baseRequest, scannedAt: "2026-08-01T10:00:00.000Z" });
    const second = await ingestion.ingest({
      ...baseRequest,
      scannedAt: "2026-08-02T10:00:00.000Z",
    });

    expect(second.summary.created).toBe(0);
    expect(second.summary.updated).toBe(2);
    expect((await findings.findAll()).total).toBe(2);
  });

  it("advances lastDetectedAt but never firstDetectedAt on a repeat scan", async () => {
    const { ingestion, findings } = build();

    await ingestion.ingest({ ...baseRequest, scannedAt: "2026-08-01T10:00:00.000Z" });
    await ingestion.ingest({ ...baseRequest, scannedAt: "2026-08-05T10:00:00.000Z" });

    const page = await findings.findAll();
    page.items.forEach((finding) => {
      expect(finding.firstDetectedAt).toBe("2026-08-01T10:00:00.000Z");
      expect(finding.lastDetectedAt).toBe("2026-08-05T10:00:00.000Z");
    });
  });

  it("auto-resolves findings the scan no longer reports", async () => {
    const { ingestion, findings } = build();

    await ingestion.ingest({ ...baseRequest, scannedAt: "2026-08-01T10:00:00.000Z" });

    // Second scan reports only the first result.
    const trimmed = structuredClone(semgrepJson) as { results: unknown[] };
    trimmed.results = [trimmed.results[0]];

    const second = await ingestion.ingest({
      ...baseRequest,
      results: trimmed,
      scannedAt: "2026-08-06T10:00:00.000Z",
    });

    expect(second.summary.resolved).toBe(1);

    const resolved = (await findings.findAll({ status: ["RESOLVED"] })).items;
    expect(resolved).toHaveLength(1);
    expect(resolved[0].resolvedAt).toBe("2026-08-06T10:00:00.000Z");
  });

  it("reopens a finding that comes back", async () => {
    const { ingestion, findings } = build();

    await ingestion.ingest({ ...baseRequest, scannedAt: "2026-08-01T10:00:00.000Z" });

    const trimmed = structuredClone(semgrepJson) as { results: unknown[] };
    trimmed.results = [trimmed.results[0]];
    await ingestion.ingest({
      ...baseRequest,
      results: trimmed,
      scannedAt: "2026-08-06T10:00:00.000Z",
    });

    const third = await ingestion.ingest({
      ...baseRequest,
      scannedAt: "2026-08-10T10:00:00.000Z",
    });

    expect(third.summary.reopened).toBe(1);
    expect((await findings.findAll({ status: ["RESOLVED"] })).total).toBe(0);
    expect((await findings.findAll({ status: ["OPEN"] })).total).toBe(2);
  });

  it("does not resolve another scanner's findings", async () => {
    const { ingestion, findings } = build();

    await ingestion.ingest({ ...baseRequest, scannedAt: "2026-08-01T10:00:00.000Z" });
    await ingestion.ingest({
      scanner: "TRIVY",
      repositoryId: "repo_payment",
      repositoryName: "payment-service",
      results: trivyJson,
      scannedAt: "2026-08-01T11:00:00.000Z",
    });

    // Semgrep findings survive a Trivy scan that reports different problems.
    expect((await findings.findAll({ scanner: ["SEMGREP"], status: ["OPEN"] })).total).toBe(2);
    expect((await findings.findAll({ scanner: ["TRIVY"], status: ["OPEN"] })).total).toBe(4);
  });

  it("honours autoResolveMissing=false for partial scans", async () => {
    const { ingestion, findings } = build();

    await ingestion.ingest({ ...baseRequest, scannedAt: "2026-08-01T10:00:00.000Z" });

    await ingestion.ingest({
      ...baseRequest,
      results: { results: [] },
      scannedAt: "2026-08-02T10:00:00.000Z",
      autoResolveMissing: false,
    });

    expect((await findings.findAll({ status: ["OPEN"] })).total).toBe(2);
  });

  it("collapses duplicates inside a single payload", async () => {
    const { ingestion } = build();

    const doubled = structuredClone(semgrepJson) as { results: unknown[] };
    doubled.results = [...doubled.results, ...doubled.results];

    const result = await ingestion.ingest({ ...baseRequest, results: doubled });

    expect(result.summary.received).toBe(4);
    expect(result.summary.duplicatesInPayload).toBe(2);
    expect(result.summary.created).toBe(2);
  });

  it("routes a mislabelled payload to the adapter that actually owns it", async () => {
    const { ingestion } = build();

    const result = await ingestion.ingest({
      ...baseRequest,
      scanner: "CHECKOV",
      results: semgrepJson,
    });

    expect(result.scanRun.scanner).toBe("SEMGREP");
    expect(result.findings.every((finding) => finding.scanner === "SEMGREP")).toBe(
      true,
    );
  });

  it("records a FAILED scan run instead of throwing past the caller", async () => {
    const { ingestion, runs } = build();

    await expect(
      ingestion.ingest({
        scanner: "SEMGREP",
        repositoryName: "payment-service",
        // Structurally SARIF, but a version the parser refuses.
        results: { version: "1.0.0", runs: [], $schema: "sarif" },
      }),
    ).rejects.toBeInstanceOf(InvalidSarifError);

    const recorded = await runs.findAll();
    expect(recorded[0].status).toBe("FAILED");
    expect(recorded[0].error).toContain("SARIF");
  });

  it("keeps scanner payloads out of failure telemetry", async () => {
    const { ingestion, runs } = build();

    await ingestion
      .ingest({
        scanner: "SEMGREP",
        repositoryName: "payment-service",
        results: { version: "1.0.0", runs: [], $schema: "sarif" },
      })
      .catch(() => undefined);

    const [failed] = await runs.findAll();
    // The stored error is a domain message, never a serialized payload.
    expect(failed.error).not.toContain("{");
    expect(failed.error!.length).toBeLessThan(200);
  });

  it("emits observability events for the ingestion lifecycle", async () => {
    const { ingestion } = build();

    await ingestion.ingest({ ...baseRequest, scannedAt: "2026-08-01T10:00:00.000Z" });

    const counters = getSecurityEventCounters();
    expect(counters["scan.ingestion.started"]).toBe(1);
    expect(counters["scan.ingestion.succeeded"]).toBe(1);
    expect(counters["scan.findings.processed"]).toBe(1);
    expect(counters["scan.findings.created"]).toBe(1);
  });

  it("propagates scan context onto every finding", async () => {
    const { ingestion, findings } = build();

    await ingestion.ingest({
      ...baseRequest,
      applicationId: "app_payments",
      commitSha: "abc1234",
      workflowRunId: "99",
      scannedAt: "2026-08-01T10:00:00.000Z",
    });

    const page = await findings.findAll();
    page.items.forEach((finding) => {
      expect(finding.repositoryName).toBe("payment-service");
      expect(finding.applicationId).toBe("app_payments");
      expect(finding.environment).toBe("production");
      expect(finding.commitSha).toBe("abc1234");
    });
  });
});

describe("dedupeByFingerprint", () => {
  const make = (fingerprint: string, severity: "HIGH" | "LOW") => ({
    id: fingerprint,
    fingerprint,
    scanner: "TRIVY" as const,
    category: "SCA" as const,
    severity,
    title: "t",
    status: "OPEN" as const,
    firstDetectedAt: "2026-08-01T00:00:00.000Z",
    lastDetectedAt: "2026-08-01T00:00:00.000Z",
  });

  it("keeps one entry per fingerprint", () => {
    const { unique, duplicates } = dedupeByFingerprint([
      make("a", "HIGH"),
      make("a", "HIGH"),
      make("b", "LOW"),
    ]);

    expect(unique).toHaveLength(2);
    expect(duplicates).toBe(1);
  });

  it("keeps the more severe duplicate regardless of payload order", () => {
    const lowFirst = dedupeByFingerprint([make("a", "LOW"), make("a", "HIGH")]);
    const highFirst = dedupeByFingerprint([make("a", "HIGH"), make("a", "LOW")]);

    expect(lowFirst.unique[0].severity).toBe("HIGH");
    expect(highFirst.unique[0].severity).toBe("HIGH");
  });
});
