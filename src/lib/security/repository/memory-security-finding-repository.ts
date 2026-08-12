import type { FindingDecision } from "@/domain/security/decision";
import { SEVERITY_RANK } from "@/domain/security/enums";
import {
  emptySeverityCounts,
  type FindingFilters,
  type FindingQuery,
  type FindingStatistics,
  type Page,
  type RepositorySecuritySummary,
  type SecurityFinding,
  type TrendPoint,
} from "@/domain/security/finding";
import type { ResolutionScope } from "../lifecycle";
import type {
  FilterOptions,
  SecurityFindingRepository,
  StatisticsWindow,
} from "./security-finding-repository";

/**
 * In-memory finding store.
 *
 * The right amount of infrastructure for this stage: no database to run, no
 * migrations to maintain, and it exercises the full repository interface so the
 * PostgreSQL implementation has a contract to satisfy rather than a shape to
 * invent.
 *
 * Limitations, stated rather than discovered: state is per process and is lost
 * on restart, and in a multi-instance deployment each instance would hold a
 * different set. That is acceptable for development and for a single-instance
 * demo, and is exactly why persistence sits behind an interface.
 */
export class InMemorySecurityFindingRepository
  implements SecurityFindingRepository
{
  /** fingerprint -> finding. Fingerprint is the natural key; id is derived. */
  private readonly findings = new Map<string, SecurityFinding>();

  /** finding id -> decisions in append order. Sorted on read, like Postgres. */
  private readonly decisions = new Map<string, FindingDecision[]>();

  constructor(seed: readonly SecurityFinding[] = []) {
    seed.forEach((finding) => this.findings.set(finding.fingerprint, finding));
  }

  // --- reads ---------------------------------------------------------------

  async findAll(query: FindingQuery = {}): Promise<Page<SecurityFinding>> {
    const matched = this.match(query);
    const sorted = sortFindings(
      matched,
      query.sortBy ?? "severity",
      query.sortDirection ?? "desc",
    );

    const pageSize = clamp(query.pageSize ?? 25, 1, 200);
    const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
    const page = clamp(query.page ?? 1, 1, totalPages);
    const start = (page - 1) * pageSize;

    return {
      items: sorted.slice(start, start + pageSize),
      total: sorted.length,
      page,
      pageSize,
      totalPages,
    };
  }

  async findById(id: string): Promise<SecurityFinding | null> {
    for (const finding of this.findings.values()) {
      if (finding.id === id) return finding;
    }
    return null;
  }

  async findByFingerprint(
    fingerprint: string,
  ): Promise<SecurityFinding | null> {
    return this.findings.get(fingerprint) ?? null;
  }

  async findManyByFingerprints(
    fingerprints: readonly string[],
  ): Promise<Map<string, SecurityFinding>> {
    const output = new Map<string, SecurityFinding>();
    for (const fingerprint of fingerprints) {
      const finding = this.findings.get(fingerprint);
      if (finding) output.set(fingerprint, finding);
    }
    return output;
  }

  async findByScope(scope: ResolutionScope): Promise<SecurityFinding[]> {
    return [...this.findings.values()].filter((finding) => {
      if (finding.scanner !== scope.scanner) return false;
      if (scope.repositoryId || finding.repositoryId) {
        return finding.repositoryId === scope.repositoryId;
      }
      return finding.repositoryName === scope.repositoryName;
    });
  }

  async count(filters: FindingFilters = {}): Promise<number> {
    return this.match(filters).length;
  }

  // --- writes --------------------------------------------------------------

  async save(finding: SecurityFinding): Promise<SecurityFinding> {
    this.findings.set(finding.fingerprint, finding);
    return finding;
  }

  async saveMany(
    findings: readonly SecurityFinding[],
  ): Promise<SecurityFinding[]> {
    findings.forEach((finding) =>
      this.findings.set(finding.fingerprint, finding),
    );
    return [...findings];
  }

  async update(
    id: string,
    patch: Partial<SecurityFinding>,
  ): Promise<SecurityFinding | null> {
    const existing = await this.findById(id);
    if (!existing) return null;

    // Identity is not patchable: allowing it would silently orphan history.
    const { id: _id, fingerprint: _fingerprint, ...safePatch } = patch;
    void _id;
    void _fingerprint;

    const updated: SecurityFinding = { ...existing, ...safePatch };
    this.findings.set(existing.fingerprint, updated);
    return updated;
  }

  async recordDecision(
    id: string,
    patch: Partial<SecurityFinding>,
    decision: FindingDecision,
  ): Promise<SecurityFinding | null> {
    const existing = await this.findById(id);
    if (!existing) return null;

    // Identity is not patchable: allowing it would silently orphan history.
    const { id: _id, fingerprint: _fingerprint, ...safePatch } = patch;
    void _id;
    void _fingerprint;

    // One synchronous block: the finding update and the append cannot be
    // observed half-done, which is the transaction the Postgres driver runs.
    const updated: SecurityFinding = { ...existing, ...safePatch };
    this.findings.set(existing.fingerprint, updated);

    const history = this.decisions.get(id) ?? [];
    // Same idempotency Postgres gets from ON CONFLICT (id) DO NOTHING: a
    // replayed decision id is not appended twice.
    if (!history.some((entry) => entry.id === decision.id)) {
      history.push({ ...decision });
    }
    this.decisions.set(id, history);

    return updated;
  }

  async listDecisionHistory(id: string): Promise<FindingDecision[]> {
    const history = this.decisions.get(id) ?? [];
    return [...history].sort(
      (a, b) =>
        b.decidedAt.localeCompare(a.decidedAt) || b.id.localeCompare(a.id),
    );
  }

  // --- aggregates ----------------------------------------------------------

  async getStatistics(
    filters: FindingFilters = {},
    window: StatisticsWindow = {},
  ): Promise<FindingStatistics> {
    const matched = this.match(filters);

    const from = window.from ? Date.parse(window.from) : undefined;
    const to = window.to ? Date.parse(window.to) : Date.now();

    const stats: FindingStatistics = {
      total: matched.length,
      totalOpen: 0,
      totalResolved: 0,
      totalAcceptedRisk: 0,
      totalFalsePositive: 0,
      totalSuppressed: 0,
      bySeverity: emptySeverityCounts(),
      byScanner: {},
      byCategory: {},
      byRepository: {},
      byEnvironment: {},
      newFindings: 0,
      resolvedFindings: 0,
    };

    let remediationHoursTotal = 0;
    let remediationCount = 0;

    for (const finding of matched) {
      switch (finding.status) {
        case "OPEN":
          stats.totalOpen += 1;
          break;
        case "RESOLVED":
          stats.totalResolved += 1;
          break;
        case "ACCEPTED_RISK":
          stats.totalAcceptedRisk += 1;
          break;
        case "FALSE_POSITIVE":
          stats.totalFalsePositive += 1;
          break;
        case "SUPPRESSED":
          stats.totalSuppressed += 1;
          break;
      }

      // Breakdowns describe CURRENT RISK, so they count open findings only.
      // Mixing resolved findings in would make the donut disagree with the
      // headline "total open" number.
      if (finding.status === "OPEN") {
        stats.bySeverity[finding.severity] += 1;
        increment(stats.byScanner, finding.scanner);
        increment(stats.byCategory, finding.category);
        increment(stats.byRepository, finding.repositoryName ?? "unassigned");
        increment(stats.byEnvironment, finding.environment ?? "unassigned");
      }

      const firstDetected = Date.parse(finding.firstDetectedAt);
      if (
        Number.isFinite(firstDetected) &&
        (from === undefined || firstDetected >= from) &&
        firstDetected <= to
      ) {
        stats.newFindings += 1;
      }

      if (finding.resolvedAt) {
        const resolved = Date.parse(finding.resolvedAt);
        if (
          Number.isFinite(resolved) &&
          (from === undefined || resolved >= from) &&
          resolved <= to
        ) {
          stats.resolvedFindings += 1;
          if (Number.isFinite(firstDetected) && resolved >= firstDetected) {
            remediationHoursTotal += (resolved - firstDetected) / 3_600_000;
            remediationCount += 1;
          }
        }
      }
    }

    if (remediationCount > 0) {
      // Left undefined when nothing was resolved: zero would read as
      // "remediated instantly", which is the opposite of the truth.
      stats.meanTimeToRemediateHours =
        Math.round((remediationHoursTotal / remediationCount) * 10) / 10;
    }

    return stats;
  }

  async getTrend(
    days: number,
    filters: FindingFilters = {},
    now: Date = new Date(),
  ): Promise<TrendPoint[]> {
    const matched = this.match(filters);
    const dayCount = clamp(days, 1, 365);

    const points: TrendPoint[] = [];
    const today = startOfUtcDay(now);

    for (let offset = dayCount - 1; offset >= 0; offset -= 1) {
      const dayStart = today - offset * DAY_MS;
      const dayEnd = dayStart + DAY_MS;

      let open = 0;
      let created = 0;
      let resolved = 0;

      for (const finding of matched) {
        const firstDetected = Date.parse(finding.firstDetectedAt);
        if (!Number.isFinite(firstDetected)) continue;

        const resolvedAt = finding.resolvedAt
          ? Date.parse(finding.resolvedAt)
          : undefined;

        if (firstDetected >= dayStart && firstDetected < dayEnd) created += 1;
        if (
          resolvedAt !== undefined &&
          Number.isFinite(resolvedAt) &&
          resolvedAt >= dayStart &&
          resolvedAt < dayEnd
        ) {
          resolved += 1;
        }

        // Open at the close of this day: already detected, and either never
        // resolved or resolved after the day ended.
        const wasResolvedBeforeDayEnd =
          resolvedAt !== undefined &&
          Number.isFinite(resolvedAt) &&
          resolvedAt < dayEnd;
        if (firstDetected < dayEnd && !wasResolvedBeforeDayEnd) open += 1;
      }

      points.push({
        date: new Date(dayStart).toISOString().slice(0, 10),
        open,
        new: created,
        resolved,
      });
    }

    return points;
  }

  async getRepositorySummaries(
    filters: FindingFilters = {},
  ): Promise<RepositorySecuritySummary[]> {
    const matched = this.match(filters);
    const byRepository = new Map<string, SecurityFinding[]>();

    for (const finding of matched) {
      const key = finding.repositoryName ?? "unassigned";
      const bucket = byRepository.get(key);
      if (bucket) bucket.push(finding);
      else byRepository.set(key, [finding]);
    }

    const summaries: RepositorySecuritySummary[] = [];

    for (const [repositoryName, findings] of byRepository) {
      const open = findings.filter((finding) => finding.status === "OPEN");
      const bySeverity = emptySeverityCounts();
      open.forEach((finding) => {
        bySeverity[finding.severity] += 1;
      });

      const scanners = new Map<string, number>();
      findings.forEach((finding) => {
        scanners.set(
          finding.scanner,
          (scanners.get(finding.scanner) ?? 0) +
            (finding.status === "OPEN" ? 1 : 0),
        );
      });

      summaries.push({
        repositoryName,
        repositoryId: findings[0]?.repositoryId,
        openFindings: open.length,
        bySeverity,
        scanners: [...scanners.entries()].map(([scanner, openFindings]) => ({
          scanner: scanner as SecurityFinding["scanner"],
          status: openFindings > 0 ? "FAILED" : "PASSED",
          openFindings,
        })),
      });
    }

    return summaries.sort((a, b) => b.openFindings - a.openFindings);
  }

  async listFilterOptions(): Promise<FilterOptions> {
    const repositories = new Set<string>();
    const environments = new Set<string>();
    const scanners = new Set<string>();
    const categories = new Set<string>();

    for (const finding of this.findings.values()) {
      if (finding.repositoryName) repositories.add(finding.repositoryName);
      if (finding.environment) environments.add(finding.environment);
      scanners.add(finding.scanner);
      categories.add(finding.category);
    }

    return {
      repositories: [...repositories].sort(),
      environments: [...environments].sort(),
      scanners: [...scanners].sort(),
      categories: [...categories].sort(),
    };
  }

  // --- internals -----------------------------------------------------------

  private match(filters: FindingFilters): SecurityFinding[] {
    return [...this.findings.values()].filter((finding) =>
      matchesFilters(finding, filters),
    );
  }
}

const DAY_MS = 86_400_000;

function startOfUtcDay(date: Date): number {
  return Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate(),
  );
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(Math.max(Math.trunc(value), min), max);
}

function increment(target: Record<string, number>, key: string): void {
  target[key] = (target[key] ?? 0) + 1;
}

function includesIfPresent<T>(
  allowed: readonly T[] | undefined,
  value: T,
): boolean {
  return !allowed || allowed.length === 0 || allowed.includes(value);
}

/**
 * Filter predicate, shared by every read path so the API, the statistics and
 * the trend can never disagree about what a filter means.
 */
export function matchesFilters(
  finding: SecurityFinding,
  filters: FindingFilters,
): boolean {
  if (!includesIfPresent(filters.severity, finding.severity)) return false;
  if (!includesIfPresent(filters.scanner, finding.scanner)) return false;
  if (!includesIfPresent(filters.category, finding.category)) return false;
  if (!includesIfPresent(filters.status, finding.status)) return false;

  if (filters.repository?.length) {
    if (
      !finding.repositoryName ||
      !filters.repository.includes(finding.repositoryName)
    ) {
      return false;
    }
  }

  if (filters.environment?.length) {
    if (
      !finding.environment ||
      !filters.environment.includes(finding.environment)
    ) {
      return false;
    }
  }

  if (filters.detectedSince) {
    const since = Date.parse(filters.detectedSince);
    const lastDetected = Date.parse(finding.lastDetectedAt);
    if (
      Number.isFinite(since) &&
      Number.isFinite(lastDetected) &&
      lastDetected < since
    ) {
      return false;
    }
  }

  if (filters.search) {
    const needle = filters.search.trim().toLowerCase();
    if (needle !== "" && !matchesSearch(finding, needle)) return false;
  }

  return true;
}

/** Search covers exactly the fields documented in the README. */
function matchesSearch(finding: SecurityFinding, needle: string): boolean {
  const haystack = [
    finding.title,
    finding.cve,
    finding.cwe,
    finding.repositoryName,
    finding.file,
    finding.resource,
    finding.ruleId,
    finding.packageName,
    finding.azureResourceId,
  ];

  return haystack.some(
    (value) => typeof value === "string" && value.toLowerCase().includes(needle),
  );
}

export function sortFindings(
  findings: readonly SecurityFinding[],
  sortBy: NonNullable<FindingQuery["sortBy"]>,
  direction: "asc" | "desc",
): SecurityFinding[] {
  const factor = direction === "asc" ? 1 : -1;

  return [...findings].sort((a, b) => {
    const primary = compareBy(a, b, sortBy) * factor;
    if (primary !== 0) return primary;

    // Stable, meaningful tiebreak: severity, then most recently seen, then id.
    const bySeverity =
      (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    if (bySeverity !== 0) return bySeverity;

    const byRecency = b.lastDetectedAt.localeCompare(a.lastDetectedAt);
    if (byRecency !== 0) return byRecency;

    return a.id.localeCompare(b.id);
  });
}

function compareBy(
  a: SecurityFinding,
  b: SecurityFinding,
  sortBy: NonNullable<FindingQuery["sortBy"]>,
): number {
  switch (sortBy) {
    case "severity":
      return (
        (SEVERITY_RANK[a.severity] ?? 0) - (SEVERITY_RANK[b.severity] ?? 0)
      );
    case "title":
      return a.title.localeCompare(b.title);
    case "firstDetectedAt":
      return a.firstDetectedAt.localeCompare(b.firstDetectedAt);
    case "lastDetectedAt":
      return a.lastDetectedAt.localeCompare(b.lastDetectedAt);
    default:
      return 0;
  }
}
