import { beforeEach, describe, expect, it } from "vitest";

import type { SecurityFinding } from "@/domain/security/finding";
import type { SecurityFindingRepository } from "@/lib/security/repository/security-finding-repository";

/**
 * Behavioural contract for SecurityFindingRepository.
 *
 * Run against every implementation. The whole promise of the repository
 * interface is that persistence is swappable; that promise is only real if the
 * in-memory and PostgreSQL stores answer identically, including the awkward
 * cases — NULL handling in filters, page clamping, tiebreak ordering, and MTTR
 * being undefined rather than zero.
 *
 * A behaviour asserted here is a behaviour the application may rely on.
 */

const NOW = new Date("2026-08-10T12:00:00.000Z");

export function finding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  const fingerprint = overrides.fingerprint ?? "fp_default";
  return {
    id: overrides.id ?? `fnd_${fingerprint}`,
    fingerprint,
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

export const CONTRACT_DATASET: SecurityFinding[] = [
  finding({ fingerprint: "a", severity: "CRITICAL" }),
  finding({
    fingerprint: "b",
    severity: "HIGH",
    scanner: "TRIVY",
    category: "SCA",
    packageName: "lodash",
    cve: "CVE-2026-3456",
  }),
  finding({
    fingerprint: "c",
    severity: "MEDIUM",
    repositoryName: "user-service",
  }),
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
  // No repository and no environment: exercises NULL handling in filters.
  finding({
    fingerprint: "h",
    severity: "LOW",
    repositoryName: undefined,
    environment: undefined,
  }),
];

export interface ContractHarness {
  /** Fresh, empty repository. */
  create(): Promise<SecurityFindingRepository>;
}

export function runSecurityFindingRepositoryContract(
  name: string,
  harness: ContractHarness,
): void {
  describe(`SecurityFindingRepository contract: ${name}`, () => {
    let repository: SecurityFindingRepository;

    beforeEach(async () => {
      repository = await harness.create();
      await repository.saveMany(CONTRACT_DATASET);
    });

    // --- reads -------------------------------------------------------------

    it("round-trips every field of a finding", async () => {
      const rich = finding({
        fingerprint: "rich",
        description: "desc",
        repositoryId: "repo_1",
        branch: "main",
        commitSha: "abc1234",
        applicationId: "app_1",
        file: "src/a.ts",
        startLine: 12,
        endLine: 14,
        packageName: "pkg",
        packageVersion: "1.0.0",
        fixedVersion: "1.0.1",
        cve: "CVE-2026-0001",
        cwe: "CWE-89",
        ruleId: "rule.a",
        resource: "azurerm_storage_account.x",
        azureResourceId: "/subscriptions/s/rg/r",
        subscriptionId: "sub-1",
        resourceGroup: "rg-1",
        remediation: "do the thing",
        sourceUrl: "https://example.invalid/a",
        resolvedAt: "2026-08-09T00:00:00.000Z",
        status: "RESOLVED",
        metadata: { owasp: ["A03"], nested: { a: 1 }, flag: true },
        statusReason: "Accepted while the vendor patch is in flight.",
        statusChangedAt: "2026-08-08T11:30:00.000Z",
        statusChangedBy: "approver@example.com",
      });

      await repository.save(rich);
      expect(await repository.findByFingerprint("rich")).toEqual(rich);
    });

    it("omits absent optional fields rather than returning null", async () => {
      const stored = await repository.findByFingerprint("a");
      expect(stored?.description).toBeUndefined();
      expect(stored?.cve).toBeUndefined();
      expect(stored?.resolvedAt).toBeUndefined();
      expect(stored?.metadata).toBeUndefined();
      expect(stored?.statusReason).toBeUndefined();
      expect(stored?.statusChangedAt).toBeUndefined();
      expect(stored?.statusChangedBy).toBeUndefined();
    });

    it("finds by id and by fingerprint, and returns null when absent", async () => {
      const byFingerprint = await repository.findByFingerprint("a");
      expect(byFingerprint?.fingerprint).toBe("a");

      const byId = await repository.findById(byFingerprint!.id);
      expect(byId?.fingerprint).toBe("a");

      expect(await repository.findById("fnd_missing")).toBeNull();
      expect(await repository.findByFingerprint("missing")).toBeNull();
    });

    it("bulk-loads fingerprints and ignores unknown ones", async () => {
      const found = await repository.findManyByFingerprints(["a", "b", "nope"]);
      expect([...found.keys()].sort()).toEqual(["a", "b"]);
      expect(await repository.findManyByFingerprints([])).toEqual(new Map());
    });

    it("counts with and without filters", async () => {
      expect(await repository.count()).toBe(CONTRACT_DATASET.length);
      expect(await repository.count({ status: ["OPEN"] })).toBe(5);
    });

    // --- filtering ---------------------------------------------------------

    it("filters by each dimension", async () => {
      expect((await repository.findAll({ severity: ["CRITICAL"] })).total).toBe(2);
      expect((await repository.findAll({ scanner: ["TRIVY"] })).total).toBe(1);
      expect((await repository.findAll({ category: ["SCA"] })).total).toBe(1);
      expect((await repository.findAll({ status: ["ACCEPTED_RISK"] })).total).toBe(1);
      expect(
        (await repository.findAll({ repository: ["user-service"] })).total,
      ).toBe(1);
      expect((await repository.findAll({ environment: ["staging"] })).total).toBe(1);
    });

    it("accepts multiple values per dimension", async () => {
      const result = await repository.findAll({
        severity: ["CRITICAL", "LOW"],
      });
      expect(result.total).toBe(4);
    });

    it("combines dimensions with AND", async () => {
      const result = await repository.findAll({
        severity: ["HIGH"],
        status: ["OPEN"],
        environment: ["production"],
      });
      expect(result.total).toBe(1);
      expect(result.items[0].fingerprint).toBe("b");
    });

    it("excludes rows with a NULL value when that dimension is filtered", async () => {
      // Finding "h" has no repository and no environment; it must not appear
      // under any specific repository or environment filter.
      const byRepository = await repository.findAll({
        repository: ["payment-service"],
      });
      expect(byRepository.items.some((f) => f.fingerprint === "h")).toBe(false);

      const byEnvironment = await repository.findAll({
        environment: ["production"],
      });
      expect(byEnvironment.items.some((f) => f.fingerprint === "h")).toBe(false);
    });

    it("ignores empty filter arrays", async () => {
      const result = await repository.findAll({ severity: [], scanner: [] });
      expect(result.total).toBe(CONTRACT_DATASET.length);
    });

    it("filters by detectedSince", async () => {
      const result = await repository.findAll({
        detectedSince: "2026-07-01T00:00:00.000Z",
      });
      // "g" was last detected in June.
      expect(result.items.some((f) => f.fingerprint === "g")).toBe(false);
      expect(result.total).toBe(CONTRACT_DATASET.length - 1);
    });

    // --- search ------------------------------------------------------------

    it("searches across title, CVE and package, case-insensitively", async () => {
      expect((await repository.findAll({ search: "CVE-2026-3456" })).total).toBe(1);
      expect((await repository.findAll({ search: "cve-2026-3456" })).total).toBe(1);
      expect((await repository.findAll({ search: "lodash" })).total).toBe(1);
      expect((await repository.findAll({ search: "no-such-thing" })).total).toBe(0);
    });

    it("treats LIKE metacharacters in a search as literal text", async () => {
      await repository.save(
        finding({ fingerprint: "pct", title: "coverage dropped 100% today" }),
      );

      // A bare "%" must not match every row.
      const wildcard = await repository.findAll({ search: "%" });
      expect(wildcard.total).toBe(1);
      expect(wildcard.items[0].fingerprint).toBe("pct");

      // Underscore is the single-character wildcard in LIKE.
      const underscore = await repository.findAll({ search: "a_b" });
      expect(underscore.total).toBe(0);
    });

    // --- sorting and pagination -------------------------------------------

    it("sorts by severity, worst first, by default", async () => {
      const result = await repository.findAll({ status: ["OPEN"] });
      expect(result.items[0].severity).toBe("CRITICAL");
      expect(result.items.at(-1)?.severity).toBe("LOW");
    });

    it("sorts ascending when asked", async () => {
      const result = await repository.findAll({
        status: ["OPEN"],
        sortBy: "severity",
        sortDirection: "asc",
      });
      expect(result.items[0].severity).toBe("LOW");
    });

    it("sorts by detection timestamps", async () => {
      const oldest = await repository.findAll({
        sortBy: "firstDetectedAt",
        sortDirection: "asc",
      });
      expect(oldest.items[0].fingerprint).toBe("g");
    });

    it("orders deterministically for equal sort keys", async () => {
      const first = await repository.findAll({ sortBy: "title" });
      const second = await repository.findAll({ sortBy: "title" });
      expect(first.items.map((f) => f.id)).toEqual(second.items.map((f) => f.id));
    });

    it("paginates without dropping or repeating rows", async () => {
      const pageOne = await repository.findAll({ pageSize: 3, page: 1 });
      const pageTwo = await repository.findAll({ pageSize: 3, page: 2 });
      const pageThree = await repository.findAll({ pageSize: 3, page: 3 });

      expect(pageOne.items).toHaveLength(3);
      expect(pageOne.totalPages).toBe(3);
      expect(pageThree.items).toHaveLength(2);

      const ids = [...pageOne.items, ...pageTwo.items, ...pageThree.items].map(
        (f) => f.id,
      );
      expect(new Set(ids).size).toBe(CONTRACT_DATASET.length);
    });

    it("clamps an out-of-range page instead of returning nothing", async () => {
      const result = await repository.findAll({ page: 99, pageSize: 5 });
      expect(result.page).toBe(2);
      expect(result.items.length).toBeGreaterThan(0);
    });

    it("clamps page size to the supported bounds", async () => {
      expect((await repository.findAll({ pageSize: 0 })).pageSize).toBe(1);
      expect((await repository.findAll({ pageSize: 5000 })).pageSize).toBe(200);
    });

    it("reports one empty page when nothing matches", async () => {
      const result = await repository.findAll({ search: "no-such-thing" });
      expect(result.items).toEqual([]);
      expect(result.total).toBe(0);
      expect(result.page).toBe(1);
      expect(result.totalPages).toBe(1);
    });

    // --- writes ------------------------------------------------------------

    it("upserts on fingerprint rather than duplicating", async () => {
      await repository.save(finding({ fingerprint: "a", severity: "LOW" }));
      expect(await repository.count()).toBe(CONTRACT_DATASET.length);
      expect((await repository.findByFingerprint("a"))?.severity).toBe("LOW");
    });

    it("saves an empty batch without error", async () => {
      await expect(repository.saveMany([])).resolves.toEqual([]);
    });

    it("saves a large batch in one call", async () => {
      const many = Array.from({ length: 250 }, (_, index) =>
        finding({ fingerprint: `bulk_${index}` }),
      );
      await repository.saveMany(many);
      expect(await repository.count()).toBe(CONTRACT_DATASET.length + 250);
    });

    it("updates by id and returns the merged finding", async () => {
      const target = await repository.findByFingerprint("a");
      const updated = await repository.update(target!.id, {
        status: "ACCEPTED_RISK",
      });

      expect(updated?.status).toBe("ACCEPTED_RISK");
      expect(updated?.title).toBe(target!.title);
      expect((await repository.findByFingerprint("a"))?.status).toBe(
        "ACCEPTED_RISK",
      );
    });

    it("round-trips a justification through update, and clears it", async () => {
      const target = await repository.findByFingerprint("a");

      const accepted = await repository.update(target!.id, {
        status: "ACCEPTED_RISK",
        statusReason: "Compensating control documented in RISK-88.",
        statusChangedAt: "2026-08-11T08:00:00.000Z",
        statusChangedBy: "approver@example.com",
      });
      expect(accepted?.statusReason).toBe(
        "Compensating control documented in RISK-88.",
      );
      expect(accepted?.statusChangedAt).toBe("2026-08-11T08:00:00.000Z");
      expect(accepted?.statusChangedBy).toBe("approver@example.com");

      const reloaded = await repository.findByFingerprint("a");
      expect(reloaded?.statusReason).toBe(
        "Compensating control documented in RISK-88.",
      );
      expect(reloaded?.statusChangedAt).toBe("2026-08-11T08:00:00.000Z");
      expect(reloaded?.statusChangedBy).toBe("approver@example.com");

      const reopened = await repository.update(target!.id, {
        status: "OPEN",
        statusReason: undefined,
        statusChangedAt: "2026-08-12T08:00:00.000Z",
        statusChangedBy: undefined,
      });
      // Cleared, not stored as an empty string — the same NULL-versus-empty
      // distinction the rest of this suite guards.
      expect(reopened?.statusReason).toBeUndefined();
      expect(reopened?.statusChangedBy).toBeUndefined();
      expect(
        (await repository.findByFingerprint("a"))?.statusReason,
      ).toBeUndefined();
      expect(
        (await repository.findByFingerprint("a"))?.statusChangedBy,
      ).toBeUndefined();
    });

    it("refuses to change identity through update", async () => {
      const target = await repository.findByFingerprint("a");
      const updated = await repository.update(target!.id, {
        id: "fnd_hijacked",
        fingerprint: "hijacked",
      });

      expect(updated?.id).toBe(target!.id);
      expect(updated?.fingerprint).toBe("a");
      expect(await repository.findByFingerprint("hijacked")).toBeNull();
    });

    it("returns null when updating something that does not exist", async () => {
      expect(await repository.update("fnd_missing", { status: "OPEN" })).toBeNull();
    });

    // --- scope -------------------------------------------------------------

    it("scopes by scanner and repository name", async () => {
      const scoped = await repository.findByScope({
        scanner: "SEMGREP",
        repositoryName: "payment-service",
      });

      expect(scoped.every((f) => f.scanner === "SEMGREP")).toBe(true);
      expect(
        scoped.every((f) => f.repositoryName === "payment-service"),
      ).toBe(true);
      expect(scoped.some((f) => f.fingerprint === "c")).toBe(false);
    });

    it("scopes by repositoryId when the scan supplies one", async () => {
      await repository.saveMany([
        finding({ fingerprint: "id1", repositoryId: "repo_1" }),
        finding({ fingerprint: "id2", repositoryId: "repo_2" }),
      ]);

      const scoped = await repository.findByScope({
        scanner: "SEMGREP",
        repositoryId: "repo_1",
      });
      expect(scoped.map((f) => f.fingerprint)).toEqual(["id1"]);
    });

    // --- statistics --------------------------------------------------------

    it("counts lifecycle states separately", async () => {
      const stats = await repository.getStatistics();

      expect(stats.total).toBe(CONTRACT_DATASET.length);
      expect(stats.totalOpen).toBe(5);
      expect(stats.totalResolved).toBe(1);
      expect(stats.totalAcceptedRisk).toBe(1);
      expect(stats.totalFalsePositive).toBe(1);
      expect(stats.totalSuppressed).toBe(0);
    });

    it("breaks down open findings only", async () => {
      const stats = await repository.getStatistics();

      expect(stats.bySeverity.CRITICAL).toBe(1);
      expect(stats.bySeverity.HIGH).toBe(2);
      expect(stats.bySeverity.MEDIUM).toBe(1);
      expect(stats.bySeverity.LOW).toBe(1);

      const openTotal = Object.values(stats.bySeverity).reduce(
        (sum, value) => sum + value,
        0,
      );
      expect(openTotal).toBe(stats.totalOpen);
    });

    it("returns a fully-populated severity map even for absent severities", async () => {
      const stats = await repository.getStatistics();
      expect(stats.bySeverity.INFO).toBe(0);
      expect(stats.bySeverity.UNKNOWN).toBe(0);
    });

    it("groups by scanner, category, repository and environment", async () => {
      const stats = await repository.getStatistics();

      expect(stats.byScanner).toEqual({ SEMGREP: 4, TRIVY: 1 });
      expect(stats.byCategory).toEqual({ SAST: 4, SCA: 1 });
      expect(stats.byRepository).toEqual({
        "payment-service": 3,
        "user-service": 1,
        unassigned: 1,
      });
      expect(stats.byEnvironment).toEqual({
        production: 3,
        staging: 1,
        unassigned: 1,
      });
    });

    it("computes MTTR in hours from lifecycle timestamps", async () => {
      const stats = await repository.getStatistics();
      // "d": detected 08-01, resolved 08-03 -> 48 hours.
      expect(stats.meanTimeToRemediateHours).toBe(48);
    });

    it("leaves MTTR undefined when nothing resolved in the window", async () => {
      const stats = await repository.getStatistics(
        {},
        { from: "2026-08-05T00:00:00.000Z", to: NOW.toISOString() },
      );
      expect(stats.resolvedFindings).toBe(0);
      expect(stats.meanTimeToRemediateHours).toBeUndefined();
    });

    it("counts new and resolved findings inside the window", async () => {
      const stats = await repository.getStatistics(
        {},
        { from: "2026-07-01T00:00:00.000Z", to: NOW.toISOString() },
      );
      // "g" was first detected in June and falls outside the window.
      expect(stats.newFindings).toBe(CONTRACT_DATASET.length - 1);
      expect(stats.resolvedFindings).toBe(1);
    });

    it("applies filters to statistics", async () => {
      const stats = await repository.getStatistics({
        repository: ["payment-service"],
      });
      expect(stats.byRepository).toEqual({ "payment-service": 3 });
      expect(stats.totalOpen).toBe(3);
    });

    it("returns zeroed statistics for a filter that matches nothing", async () => {
      const stats = await repository.getStatistics({ search: "no-such-thing" });
      expect(stats.total).toBe(0);
      expect(stats.totalOpen).toBe(0);
      expect(stats.bySeverity.CRITICAL).toBe(0);
      expect(stats.byScanner).toEqual({});
      expect(stats.meanTimeToRemediateHours).toBeUndefined();
    });

    // --- trend -------------------------------------------------------------

    it("returns one point per requested day, oldest first", async () => {
      const points = await repository.getTrend(14, {}, NOW);
      expect(points).toHaveLength(14);
      expect(points[0].date).toBe("2026-07-28");
      expect(points.at(-1)?.date).toBe("2026-08-10");
    });

    it("reports open backlog, new and resolved per day", async () => {
      const points = await repository.getTrend(30, {}, NOW);
      const byDate = new Map(points.map((point) => [point.date, point]));

      // Seven of the eight findings were first detected on 08-01 ("g" dates
      // from June), and one of them ("d") resolved on 08-03.
      expect(byDate.get("2026-08-01")?.new).toBe(7);
      expect(byDate.get("2026-08-03")?.resolved).toBe(1);

      // The backlog line means "detected and not yet resolved", so it counts
      // all eight on 08-01 (June's "g" included) and drops to seven once "d"
      // resolves. Accepted-risk and false-positive findings are counted here
      // because they are unresolved, which is deliberately a different
      // question from the status breakdown's "totalOpen".
      expect(byDate.get("2026-08-01")?.open).toBe(8);
      expect(byDate.get("2026-08-03")?.open).toBe(7);
    });

    it("returns zero-filled points when nothing matches the filter", async () => {
      const points = await repository.getTrend(3, { search: "nope" }, NOW);
      expect(points).toHaveLength(3);
      expect(points.every((p) => p.open === 0 && p.new === 0)).toBe(true);
    });

    // --- summaries and options ---------------------------------------------

    it("summarises open findings per repository, busiest first", async () => {
      const summaries = await repository.getRepositorySummaries();
      const payment = summaries.find(
        (s) => s.repositoryName === "payment-service",
      );

      // payment-service has three OPEN findings: "a" (critical) plus "b" and
      // "g" (both high). The resolved, accepted and false-positive rows on the
      // same repository are excluded.
      expect(payment?.openFindings).toBe(3);
      expect(payment?.bySeverity.CRITICAL).toBe(1);
      expect(payment?.bySeverity.HIGH).toBe(2);
      expect(summaries[0].openFindings).toBeGreaterThanOrEqual(
        summaries.at(-1)!.openFindings,
      );
    });

    it("marks a scanner failed when it has open findings", async () => {
      const summaries = await repository.getRepositorySummaries();
      const payment = summaries.find(
        (s) => s.repositoryName === "payment-service",
      );
      const semgrep = payment?.scanners.find((s) => s.scanner === "SEMGREP");

      expect(semgrep?.status).toBe("FAILED");
      expect(semgrep?.openFindings).toBeGreaterThan(0);
    });

    it("lists distinct, sorted filter options", async () => {
      const options = await repository.listFilterOptions();

      expect(options.repositories).toEqual(["payment-service", "user-service"]);
      expect(options.environments).toEqual(["production", "staging"]);
      expect(options.scanners).toEqual(["SEMGREP", "TRIVY"]);
      expect(options.categories).toEqual(["SAST", "SCA"]);
    });

    it("returns empty results from an empty store", async () => {
      const empty = await harness.create();

      expect((await empty.findAll()).total).toBe(0);
      expect(await empty.count()).toBe(0);
      expect((await empty.getStatistics()).total).toBe(0);
      expect(await empty.getRepositorySummaries()).toEqual([]);
      expect(await empty.listFilterOptions()).toEqual({
        repositories: [],
        environments: [],
        scanners: [],
        categories: [],
      });
    });
  });
}
