import { randomUUID } from "node:crypto";

import type { FindingDecision } from "@/domain/security/decision";
import {
  scannerLabel,
  type FindingStatus,
  type ScannerType,
} from "@/domain/security/enums";
import type {
  FindingFilters,
  FindingQuery,
  FindingStatistics,
  Page,
  RepositorySecuritySummary,
  SecurityFinding,
  TrendPoint,
} from "@/domain/security/finding";
import type {
  ScanRun,
  ScannerHealth,
  ScanRunQuery,
} from "@/domain/security/scan-run";
import {
  InvalidStatusReasonError,
  InvalidStatusTransitionError,
} from "@/domain/security/errors";
import { canTransition, isHumanDecided } from "../lifecycle";
import { MAX_STATUS_REASON_LENGTH } from "../status-change";
import { statusReasonSchema } from "../validation/schemas";
import type {
  FilterOptions,
  SecurityFindingRepository,
} from "../repository/security-finding-repository";
import {
  deriveScannerHealth,
  InMemoryScanRunRepository,
  type ScanRunRepository,
} from "../repository/scan-run-repository";

/**
 * Read-side application service.
 *
 * Every metric the dashboard renders is computed here or in the repository —
 * never in a chart component. A chart receives numbers and draws them; if a
 * definition changes ("does an accepted risk still count as open?"), exactly
 * one file changes and every surface agrees.
 */

export type Timeframe = "24h" | "7d" | "30d" | "all";

const TIMEFRAME_HOURS: Record<Exclude<Timeframe, "all">, number> = {
  "24h": 24,
  "7d": 24 * 7,
  "30d": 24 * 30,
};

export function timeframeCutoff(
  timeframe: Timeframe,
  now: Date = new Date(),
): string | undefined {
  if (timeframe === "all") return undefined;
  return new Date(
    now.getTime() - TIMEFRAME_HOURS[timeframe] * 3_600_000,
  ).toISOString();
}

export function isTimeframe(value: unknown): value is Timeframe {
  return (
    value === "24h" || value === "7d" || value === "30d" || value === "all"
  );
}

export interface PipelineStageView {
  /** Display name of the stage, e.g. "Semgrep". */
  name: string;
  scanner: ScannerType;
  /**
   * PASSED   scan completed with no findings
   * FAILED   scan errored, or completed with findings (the gate did not pass)
   * RUNNING  scan in flight
   */
  status: "PASSED" | "FAILED" | "RUNNING";
  findings: number;
  lastRunAt?: string;
  durationSeconds?: number;
}

export interface RepositoryPipelineView {
  repositoryName: string;
  branch?: string;
  commitSha?: string;
  stages: PipelineStageView[];
  lastRunAt?: string;
}

/**
 * Conventional ordering for security stages in a pipeline diagram. Scanners not
 * listed here still appear — they sort after the known ones, alphabetically —
 * so a newly added scanner needs no change to this table.
 */
const STAGE_ORDER: Partial<Record<ScannerType, number>> = {
  SEMGREP: 1,
  GITLEAKS: 2,
  CHECKOV: 3,
  TRIVY: 4,
};

function scannerStageName(scanner: ScannerType): string {
  return scannerLabel(scanner);
}

export interface SecurityOverview {
  statistics: FindingStatistics;
  topFindings: SecurityFinding[];
  scannerHealth: ScannerHealth[];
  trend: TrendPoint[];
}

export class SecurityService {
  constructor(
    private readonly findings: SecurityFindingRepository,
    private readonly scanRuns: ScanRunRepository = new InMemoryScanRunRepository(),
    private readonly supportedScanners: readonly ScannerType[] = [],
  ) {}

  async getFindings(query: FindingQuery = {}): Promise<Page<SecurityFinding>> {
    return this.findings.findAll(query);
  }

  async getFindingById(id: string): Promise<SecurityFinding | null> {
    return this.findings.findById(id);
  }

  async getStatistics(
    filters: FindingFilters = {},
    timeframe: Timeframe = "all",
    now: Date = new Date(),
  ): Promise<FindingStatistics> {
    const cutoff = timeframeCutoff(timeframe, now);

    // The timeframe narrows BOTH which findings are considered (last seen in
    // the window) and the window used for the "new"/"resolved" counters, so
    // "23 open in the last 7 days" and "5 new in the last 7 days" describe the
    // same population.
    return this.findings.getStatistics(
      cutoff ? { ...filters, detectedSince: cutoff } : filters,
      { from: cutoff, to: now.toISOString() },
    );
  }

  async getTrend(
    days = 30,
    filters: FindingFilters = {},
    now: Date = new Date(),
  ): Promise<TrendPoint[]> {
    return this.findings.getTrend(days, filters, now);
  }

  async getRepositorySummaries(
    filters: FindingFilters = {},
  ): Promise<RepositorySecuritySummary[]> {
    const summaries = await this.findings.getRepositorySummaries(filters);
    const latestRuns = await this.scanRuns.latestByScanner();

    // Attach last-scan timestamps so a repository row can distinguish
    // "scanner passed" from "scanner has not run recently".
    return summaries.map((summary) => ({
      ...summary,
      scanners: summary.scanners.map((entry) => ({
        ...entry,
        lastScanAt: latestRuns.get(entry.scanner)?.completedAt,
      })),
    }));
  }

  async getFilterOptions(): Promise<FilterOptions> {
    return this.findings.listFilterOptions();
  }

  async getScannerHealth(now: Date = new Date()): Promise<ScannerHealth[]> {
    const latestRuns = await this.scanRuns.latestByScanner();

    // Union of "scanners we support" and "scanners that have reported", so a
    // configured-but-never-run scanner still shows up as NEVER_RUN.
    const scanners = new Set<ScannerType>([
      ...this.supportedScanners,
      ...latestRuns.keys(),
    ]);

    const runCounts =
      this.scanRuns instanceof InMemoryScanRunRepository
        ? await this.scanRuns.countByScanner()
        : new Map<ScannerType, number>();

    return deriveScannerHealth([...scanners], latestRuns, now, runCounts).sort(
      (a, b) => a.scanner.localeCompare(b.scanner),
    );
  }

  async getScanRuns(query: ScanRunQuery = {}): Promise<ScanRun[]> {
    return this.scanRuns.findAll(query);
  }

  /**
   * Everything the Overview page needs, in one call, so the page does not fan
   * out into four uncoordinated queries that could disagree.
   */
  async getOverview(
    timeframe: Timeframe = "all",
    now: Date = new Date(),
  ): Promise<SecurityOverview> {
    const [statistics, topFindings, scannerHealth, trend] = await Promise.all([
      this.getStatistics({}, timeframe, now),
      this.getTopFindings(5),
      this.getScannerHealth(now),
      this.getTrend(14, {}, now),
    ]);

    return { statistics, topFindings, scannerHealth, trend };
  }

  /** Highest-severity open findings, most recently seen first. */
  async getTopFindings(limit = 5): Promise<SecurityFinding[]> {
    const page = await this.findings.findAll({
      status: ["OPEN"],
      sortBy: "severity",
      sortDirection: "desc",
      pageSize: Math.max(1, limit),
      page: 1,
    });
    return page.items;
  }

  /**
   * Security stages of each repository's pipeline, derived from scan runs.
   *
   * Stages are NOT hardcoded: a repository shows exactly the scanners that have
   * actually reported for it. A repository scanned only by Gitleaks shows one
   * stage, and a scanner added next month appears here with no code change.
   *
   * Build/test/package/deploy stages are intentionally absent — they belong to
   * the GitHub provider, which is not connected yet, and inventing them would
   * put fictional deployments on an operational dashboard.
   */
  async getRepositoryPipelines(): Promise<RepositoryPipelineView[]> {
    const runs = await this.scanRuns.findAll({ limit: 500 });

    const byRepository = new Map<string, Map<ScannerType, (typeof runs)[number]>>();

    for (const run of runs) {
      const repositoryName = run.repositoryName ?? "unassigned";
      const stages =
        byRepository.get(repositoryName) ??
        new Map<ScannerType, (typeof runs)[number]>();

      // findAll returns newest first, so the first run seen per scanner wins.
      if (!stages.has(run.scanner)) stages.set(run.scanner, run);
      byRepository.set(repositoryName, stages);
    }

    const views: RepositoryPipelineView[] = [];

    for (const [repositoryName, stageRuns] of byRepository) {
      const stages: PipelineStageView[] = [...stageRuns.entries()]
        .map(([scanner, run]) => ({
          name: scannerStageName(scanner),
          scanner,
          status:
            run.status === "RUNNING"
              ? ("RUNNING" as const)
              : run.status === "FAILED" || run.totalFindings > 0
                ? ("FAILED" as const)
                : ("PASSED" as const),
          findings: run.totalFindings,
          lastRunAt: run.completedAt ?? run.startedAt,
          durationSeconds: run.durationSeconds,
        }))
        .sort((a, b) => {
          const orderA = STAGE_ORDER[a.scanner] ?? 99;
          const orderB = STAGE_ORDER[b.scanner] ?? 99;
          if (orderA !== orderB) return orderA - orderB;
          return a.scanner.localeCompare(b.scanner);
        });

      const newest = [...stageRuns.values()].sort((a, b) =>
        b.startedAt.localeCompare(a.startedAt),
      )[0];

      views.push({
        repositoryName,
        branch: newest?.branch,
        commitSha: newest?.commitSha,
        stages,
        lastRunAt: newest?.completedAt ?? newest?.startedAt,
      });
    }

    return views.sort((a, b) =>
      a.repositoryName.localeCompare(b.repositoryName),
    );
  }

  /**
   * Apply a human decision to a finding (accept risk, mark false positive, …).
   *
   * Invalid transitions are rejected rather than silently applied, and the three
   * human-decided statuses require a justification: an accepted risk with no
   * recorded reason is not auditable, which is the whole point of the status.
   *
   * `options.changedBy` is the deciding user's email, snapshotted onto the
   * finding and onto the appended decision. The caller supplies it from the
   * session; the service never guesses, and the type no longer lets a caller
   * omit it.
   */
  async setFindingStatus(
    id: string,
    status: FindingStatus,
    reason: string | undefined,
    options: { changedBy: string; now?: Date },
  ): Promise<SecurityFinding | null> {
    const now = options.now ?? new Date();
    const finding = await this.findings.findById(id);
    if (!finding) return null;
    // A no-op transition must not become a way to rewrite an existing
    // justification without a real state change.
    if (finding.status === status) return finding;
    if (!canTransition(finding.status, status)) {
      throw new InvalidStatusTransitionError(finding.status, status);
    }

    let statusReason: string | undefined;
    if (isHumanDecided(status)) {
      const parsed = statusReasonSchema.safeParse(reason ?? "");
      if (!parsed.success) {
        throw new InvalidStatusReasonError(
          `A justification of 1 to ${MAX_STATUS_REASON_LENGTH} characters is required to set a finding to ${status}.`,
        );
      }
      statusReason = parsed.data;
    } else if (reason !== undefined) {
      const parsed = statusReasonSchema.safeParse(reason);
      if (!parsed.success) {
        throw new InvalidStatusReasonError(
          `A justification may be at most ${MAX_STATUS_REASON_LENGTH} characters.`,
        );
      }
      statusReason = parsed.data;
    }

    const decision: FindingDecision = {
      // The service, not the driver, generates the id: recordDecision retries
      // as a whole unit, and a replay after a lost COMMIT acknowledgement must
      // dedupe on a stable id rather than append a second row.
      id: `dec_${randomUUID()}`,
      findingId: id,
      fromStatus: finding.status,
      toStatus: status,
      reason: statusReason,
      decidedBy: options.changedBy,
      decidedAt: now.toISOString(),
    };

    return this.findings.recordDecision(
      id,
      {
        status,
        resolvedAt: status === "RESOLVED" ? now.toISOString() : undefined,
        // Reopening without a reason clears the old one: a justification written
        // for a status the finding no longer holds reads as a current decision.
        statusReason,
        statusChangedAt: now.toISOString(),
        // Attribution belongs to the change, not to the justification: this is
        // who made the change `statusChangedAt` timestamps.
        statusChangedBy: options.changedBy,
      },
      decision,
    );
  }

  /**
   * Every human decision recorded for a finding, newest first. Null when the
   * finding does not exist, so the history route can 404 exactly as the
   * sibling finding route does.
   */
  async getDecisionHistory(id: string): Promise<FindingDecision[] | null> {
    const finding = await this.findings.findById(id);
    if (!finding) return null;
    return this.findings.listDecisionHistory(id);
  }
}
