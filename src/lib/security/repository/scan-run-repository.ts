import type { ScannerType } from "@/domain/security/enums";
import type {
  ScanRun,
  ScannerHealth,
  ScannerHealthStatus,
  ScanRunQuery,
} from "@/domain/security/scan-run";

export interface ScanRunRepository {
  save(run: ScanRun): Promise<ScanRun>;
  findById(id: string): Promise<ScanRun | null>;
  findAll(query?: ScanRunQuery): Promise<ScanRun[]>;
  /** Most recent run per scanner, which is what scanner health is built from. */
  latestByScanner(): Promise<Map<ScannerType, ScanRun>>;
}

/**
 * How long a scanner may go without a successful run before the dashboard
 * stops calling it healthy. Twenty-six hours covers a nightly pipeline plus
 * slack for a late or retried run.
 */
export const SCANNER_STALE_AFTER_HOURS = 26;

/**
 * Derive scanner health from scan runs.
 *
 * Health is deliberately computed from runs, never from findings: a scanner
 * that produced zero findings and a scanner that never executed look identical
 * in the findings table, and conflating them is how a silently broken pipeline
 * gets mistaken for a clean codebase.
 */
export function deriveScannerHealth(
  scanners: readonly ScannerType[],
  latestRuns: ReadonlyMap<ScannerType, ScanRun>,
  now: Date = new Date(),
  runCounts: ReadonlyMap<ScannerType, number> = new Map(),
): ScannerHealth[] {
  return scanners.map((scanner) => {
    const run = latestRuns.get(scanner);

    if (!run) {
      return {
        scanner,
        status: "NEVER_RUN" as ScannerHealthStatus,
        runCount: 0,
      };
    }

    const reference = run.completedAt ?? run.startedAt;
    const ageHours =
      (now.getTime() - Date.parse(reference)) / 3_600_000;

    let status: ScannerHealthStatus;
    if (run.status === "FAILED") {
      status = "FAILED";
    } else if (run.status === "RUNNING") {
      // A run that has been "running" for longer than the staleness window is
      // stuck, not healthy.
      status = ageHours > SCANNER_STALE_AFTER_HOURS ? "WARNING" : "HEALTHY";
    } else if (
      !Number.isFinite(ageHours) ||
      ageHours > SCANNER_STALE_AFTER_HOURS
    ) {
      status = "WARNING";
    } else {
      status = "HEALTHY";
    }

    return {
      scanner,
      status,
      lastScanAt: reference,
      lastRunId: run.id,
      lastRunStatus: run.status,
      totalFindings: run.totalFindings,
      runCount: runCounts.get(scanner) ?? 1,
      error: run.status === "FAILED" ? run.error : undefined,
    };
  });
}

/**
 * In-memory scan run store. Same trade-offs as the finding repository: process
 * local, replaceable, sufficient for development.
 */
export class InMemoryScanRunRepository implements ScanRunRepository {
  private readonly runs = new Map<string, ScanRun>();

  constructor(seed: readonly ScanRun[] = []) {
    seed.forEach((run) => this.runs.set(run.id, run));
  }

  async save(run: ScanRun): Promise<ScanRun> {
    this.runs.set(run.id, run);
    return run;
  }

  async findById(id: string): Promise<ScanRun | null> {
    return this.runs.get(id) ?? null;
  }

  async findAll(query: ScanRunQuery = {}): Promise<ScanRun[]> {
    let runs = [...this.runs.values()];

    if (query.scanner?.length) {
      const allowed = query.scanner;
      runs = runs.filter((run) => allowed.includes(run.scanner));
    }
    if (query.repositoryName?.length) {
      const allowed = query.repositoryName;
      runs = runs.filter(
        (run) => run.repositoryName && allowed.includes(run.repositoryName),
      );
    }
    if (query.status?.length) {
      const allowed = query.status;
      runs = runs.filter((run) => allowed.includes(run.status));
    }

    runs.sort((a, b) => b.startedAt.localeCompare(a.startedAt));

    return query.limit ? runs.slice(0, Math.max(0, query.limit)) : runs;
  }

  async latestByScanner(): Promise<Map<ScannerType, ScanRun>> {
    const latest = new Map<ScannerType, ScanRun>();
    for (const run of this.runs.values()) {
      const current = latest.get(run.scanner);
      if (!current || run.startedAt > current.startedAt) {
        latest.set(run.scanner, run);
      }
    }
    return latest;
  }

  async countByScanner(): Promise<Map<ScannerType, number>> {
    const counts = new Map<ScannerType, number>();
    for (const run of this.runs.values()) {
      counts.set(run.scanner, (counts.get(run.scanner) ?? 0) + 1);
    }
    return counts;
  }
}
