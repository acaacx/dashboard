import type { FindingDecision } from "@/domain/security/decision";
import type {
  FindingFilters,
  FindingQuery,
  FindingStatistics,
  Page,
  RepositorySecuritySummary,
  SecurityFinding,
  TrendPoint,
} from "@/domain/security/finding";
import type { ResolutionScope } from "../lifecycle";

/**
 * Persistence contract for normalized findings.
 *
 * Deliberately narrow and deliberately async: every method returns a Promise so
 * the in-memory development implementation and a future PostgreSQL one are
 * drop-in interchangeable. Nothing above this interface knows where findings
 * live.
 *
 * See README "Future PostgreSQL storage" for the table shapes each method maps
 * onto.
 */
export interface SecurityFindingRepository {
  findAll(query?: FindingQuery): Promise<Page<SecurityFinding>>;

  findById(id: string): Promise<SecurityFinding | null>;

  findByFingerprint(fingerprint: string): Promise<SecurityFinding | null>;

  /** Bulk fingerprint lookup — one round trip per scan, not one per finding. */
  findManyByFingerprints(
    fingerprints: readonly string[],
  ): Promise<Map<string, SecurityFinding>>;

  /** All stored findings within a scan's resolution scope. */
  findByScope(scope: ResolutionScope): Promise<SecurityFinding[]>;

  save(finding: SecurityFinding): Promise<SecurityFinding>;

  saveMany(findings: readonly SecurityFinding[]): Promise<SecurityFinding[]>;

  update(
    id: string,
    patch: Partial<SecurityFinding>,
  ): Promise<SecurityFinding | null>;

  /**
   * Apply a status patch and append the decision that caused it, atomically:
   * both land or neither does. Returns null — writing nothing — when the
   * finding does not exist. Replay-safe: a decision id already stored is not
   * appended twice, because retry may replay a transaction whose COMMIT
   * acknowledgement was lost.
   */
  recordDecision(
    id: string,
    patch: Partial<SecurityFinding>,
    decision: FindingDecision,
  ): Promise<SecurityFinding | null>;

  /** Every recorded decision for a finding, newest first. */
  listDecisionHistory(id: string): Promise<FindingDecision[]>;

  getStatistics(
    filters?: FindingFilters,
    window?: StatisticsWindow,
  ): Promise<FindingStatistics>;

  /** `now` is injectable so trend windows are deterministic in tests. */
  getTrend(
    days: number,
    filters?: FindingFilters,
    now?: Date,
  ): Promise<TrendPoint[]>;

  getRepositorySummaries(
    filters?: FindingFilters,
  ): Promise<RepositorySecuritySummary[]>;

  /** Distinct values for populating filter dropdowns. */
  listFilterOptions(): Promise<FilterOptions>;

  count(filters?: FindingFilters): Promise<number>;
}

export interface StatisticsWindow {
  /** ISO timestamp; findings first detected at/after this count as "new". */
  from?: string;
  /** ISO timestamp; defaults to now. */
  to?: string;
}

export interface FilterOptions {
  repositories: string[];
  environments: string[];
  scanners: string[];
  categories: string[];
}
