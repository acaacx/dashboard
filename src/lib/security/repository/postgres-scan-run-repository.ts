import type { Pool } from "pg";

import type { ScannerType } from "@/domain/security/enums";
import type {
  ScanRun,
  ScanRunQuery,
  ScanRunStatus,
} from "@/domain/security/scan-run";
import { getPool } from "@/lib/db/pool";
import { withRetry } from "@/lib/db/retry";
import { recordSecurityEvent } from "../observability";
import type { ScanRunRepository } from "./scan-run-repository";

/**
 * PostgreSQL-backed scan run store.
 *
 * Scanner health is derived from these rows, so "never ran" stays
 * distinguishable from "ran and found nothing" across process restarts —
 * which is precisely what the in-memory store cannot promise.
 */

const COLUMNS = `
  id, scanner, repository_id, repository_name, branch, commit_sha,
  workflow_run_id, workflow_run_url, status,
  started_at, completed_at, ingested_at,
  critical, high, medium, low, info,
  total_findings, duration_seconds, error
`;

interface ScanRunRow {
  id: string;
  scanner: string;
  repository_id: string | null;
  repository_name: string | null;
  branch: string | null;
  commit_sha: string | null;
  workflow_run_id: string | null;
  workflow_run_url: string | null;
  status: string;
  started_at: Date;
  completed_at: Date | null;
  ingested_at: Date | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total_findings: number;
  duration_seconds: number | null;
  error: string | null;
}

function undef<T>(value: T | null): T | undefined {
  return value === null ? undefined : value;
}

function toScanRun(row: ScanRunRow): ScanRun {
  return {
    id: row.id,
    scanner: row.scanner as ScannerType,
    repositoryId: undef(row.repository_id),
    repositoryName: undef(row.repository_name),
    branch: undef(row.branch),
    commitSha: undef(row.commit_sha),
    workflowRunId: undef(row.workflow_run_id),
    workflowRunUrl: undef(row.workflow_run_url),
    status: row.status as ScanRunStatus,
    startedAt: row.started_at.toISOString(),
    completedAt: row.completed_at?.toISOString(),
    ingestedAt: row.ingested_at?.toISOString(),
    findings: {
      critical: row.critical,
      high: row.high,
      medium: row.medium,
      low: row.low,
      info: row.info,
    },
    totalFindings: row.total_findings,
    durationSeconds: undef(row.duration_seconds),
    error: undef(row.error),
  };
}

export class PostgresScanRunRepository implements ScanRunRepository {
  constructor(private readonly pool: Pool = getPool()) {}

  /** Single-statement query with transient-failure retry. */
  private async query<T>(
    text: string,
    params: readonly unknown[] = [],
    operation = "scanRuns.query",
  ): Promise<T[]> {
    return withRetry(
      async () => {
        const result = await this.pool.query(text, params as unknown[]);
        return result.rows as T[];
      },
      {
        operation,
        onRetry: (info) =>
          recordSecurityEvent("db.query.retry", {
            operation: info.operation,
            attempt: info.attempt,
            delayMs: info.delayMs,
          }),
      },
    );
  }

  async save(run: ScanRun): Promise<ScanRun> {
    await this.query(
      `INSERT INTO scan_runs (${COLUMNS})
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
       ON CONFLICT (id) DO UPDATE SET
         scanner = EXCLUDED.scanner,
         repository_id = EXCLUDED.repository_id,
         repository_name = EXCLUDED.repository_name,
         branch = EXCLUDED.branch,
         commit_sha = EXCLUDED.commit_sha,
         workflow_run_id = EXCLUDED.workflow_run_id,
         workflow_run_url = EXCLUDED.workflow_run_url,
         status = EXCLUDED.status,
         started_at = EXCLUDED.started_at,
         completed_at = EXCLUDED.completed_at,
         ingested_at = EXCLUDED.ingested_at,
         critical = EXCLUDED.critical,
         high = EXCLUDED.high,
         medium = EXCLUDED.medium,
         low = EXCLUDED.low,
         info = EXCLUDED.info,
         total_findings = EXCLUDED.total_findings,
         duration_seconds = EXCLUDED.duration_seconds,
         error = EXCLUDED.error`,
      [
        run.id,
        run.scanner,
        run.repositoryId ?? null,
        run.repositoryName ?? null,
        run.branch ?? null,
        run.commitSha ?? null,
        run.workflowRunId ?? null,
        run.workflowRunUrl ?? null,
        run.status,
        run.startedAt,
        run.completedAt ?? null,
        run.ingestedAt ?? null,
        run.findings.critical,
        run.findings.high,
        run.findings.medium,
        run.findings.low,
        run.findings.info,
        run.totalFindings,
        run.durationSeconds ?? null,
        run.error ?? null,
      ],
    );
    return run;
  }

  async findById(id: string): Promise<ScanRun | null> {
    const rows = await this.query<ScanRunRow>(
      `SELECT ${COLUMNS} FROM scan_runs WHERE id = $1`,
      [id],
    );
    return rows[0] ? toScanRun(rows[0]) : null;
  }

  async findAll(query: ScanRunQuery = {}): Promise<ScanRun[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (query.scanner?.length) {
      params.push([...query.scanner]);
      conditions.push(`scanner = ANY($${params.length}::text[])`);
    }
    if (query.repositoryName?.length) {
      params.push([...query.repositoryName]);
      conditions.push(
        `(repository_name IS NOT NULL AND repository_name = ANY($${params.length}::text[]))`,
      );
    }
    if (query.status?.length) {
      params.push([...query.status]);
      conditions.push(`status = ANY($${params.length}::text[])`);
    }

    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

    let limit = "";
    if (query.limit !== undefined) {
      params.push(Math.max(0, query.limit));
      limit = `LIMIT $${params.length}`;
    }

    const rows = await this.query<ScanRunRow>(
      `SELECT ${COLUMNS} FROM scan_runs ${where} ORDER BY started_at DESC, id DESC ${limit}`,
      params,
    );
    return rows.map(toScanRun);
  }

  async latestByScanner(): Promise<Map<ScannerType, ScanRun>> {
    const rows = await this.query<ScanRunRow>(
      `SELECT DISTINCT ON (scanner) ${COLUMNS}
       FROM scan_runs
       ORDER BY scanner, started_at DESC, id DESC`,
    );
    return new Map(
      rows.map((row) => [row.scanner as ScannerType, toScanRun(row)]),
    );
  }

  async countByScanner(): Promise<Map<ScannerType, number>> {
    const rows = await this.query<{ scanner: string; count: string }>(
      `SELECT scanner, COUNT(*)::text AS count FROM scan_runs GROUP BY scanner`,
    );
    return new Map(
      rows.map((row) => [row.scanner as ScannerType, Number(row.count)]),
    );
  }

  /** Test helper: remove every row. Never called by application code. */
  async truncate(): Promise<void> {
    await this.query("TRUNCATE scan_runs");
  }
}
