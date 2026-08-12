import type { Pool } from "pg";

import type { FindingDecision } from "@/domain/security/decision";
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
import type { ScannerType, Severity } from "@/domain/security/enums";
import { getPool } from "@/lib/db/pool";
import { withRetry } from "@/lib/db/retry";
import { recordSecurityEvent } from "../observability";
import type { ResolutionScope } from "../lifecycle";
import type {
  FilterOptions,
  SecurityFindingRepository,
  StatisticsWindow,
} from "./security-finding-repository";
import {
  buildOrderByClause,
  buildWhereClause,
  clampPageSize,
  clamp,
  ParamBuilder,
  utcDayStarts,
} from "./postgres/sql-filters";

/**
 * PostgreSQL-backed finding store.
 *
 * Behaviourally identical to InMemorySecurityFindingRepository — both are
 * verified against the same contract test suite, which is the point of the
 * repository interface. Aggregates are computed in SQL rather than by loading
 * rows into the process, so statistics stay O(index) as the dataset grows.
 */

const COLUMNS = `
  fingerprint, id, scanner, category, severity, title, description,
  repository_id, repository_name, branch, commit_sha, application_id, environment,
  file, start_line, end_line,
  package_name, package_version, fixed_version,
  cve, cwe, rule_id,
  resource, azure_resource_id, subscription_id, resource_group,
  status, first_detected_at, last_detected_at, resolved_at,
  status_reason, status_changed_at, status_changed_by,
  remediation, source_url, metadata
`;

const COLUMN_COUNT = 36;

interface FindingRow {
  fingerprint: string;
  id: string;
  scanner: string;
  category: string;
  severity: string;
  title: string;
  description: string | null;
  repository_id: string | null;
  repository_name: string | null;
  branch: string | null;
  commit_sha: string | null;
  application_id: string | null;
  environment: string | null;
  file: string | null;
  start_line: number | null;
  end_line: number | null;
  package_name: string | null;
  package_version: string | null;
  fixed_version: string | null;
  cve: string | null;
  cwe: string | null;
  rule_id: string | null;
  resource: string | null;
  azure_resource_id: string | null;
  subscription_id: string | null;
  resource_group: string | null;
  status: string;
  first_detected_at: Date;
  last_detected_at: Date;
  resolved_at: Date | null;
  status_reason: string | null;
  status_changed_at: Date | null;
  status_changed_by: string | null;
  remediation: string | null;
  source_url: string | null;
  metadata: Record<string, unknown> | null;
}

interface DecisionRow {
  id: string;
  finding_id: string;
  from_status: string;
  to_status: string;
  reason: string | null;
  decided_by: string;
  decided_at: Date;
}

function iso(value: Date | null): string | undefined {
  return value ? value.toISOString() : undefined;
}

function undef<T>(value: T | null): T | undefined {
  return value === null ? undefined : value;
}

function toFinding(row: FindingRow): SecurityFinding {
  return {
    id: row.id,
    fingerprint: row.fingerprint,
    scanner: row.scanner as SecurityFinding["scanner"],
    category: row.category as SecurityFinding["category"],
    severity: row.severity as Severity,
    title: row.title,
    description: undef(row.description),
    repositoryId: undef(row.repository_id),
    repositoryName: undef(row.repository_name),
    branch: undef(row.branch),
    commitSha: undef(row.commit_sha),
    applicationId: undef(row.application_id),
    environment: undef(row.environment),
    file: undef(row.file),
    startLine: undef(row.start_line),
    endLine: undef(row.end_line),
    packageName: undef(row.package_name),
    packageVersion: undef(row.package_version),
    fixedVersion: undef(row.fixed_version),
    cve: undef(row.cve),
    cwe: undef(row.cwe),
    ruleId: undef(row.rule_id),
    resource: undef(row.resource),
    azureResourceId: undef(row.azure_resource_id),
    subscriptionId: undef(row.subscription_id),
    resourceGroup: undef(row.resource_group),
    status: row.status as SecurityFinding["status"],
    firstDetectedAt: row.first_detected_at.toISOString(),
    lastDetectedAt: row.last_detected_at.toISOString(),
    resolvedAt: iso(row.resolved_at),
    statusReason: undef(row.status_reason),
    statusChangedAt: iso(row.status_changed_at),
    statusChangedBy: undef(row.status_changed_by),
    remediation: undef(row.remediation),
    sourceUrl: undef(row.source_url),
    metadata: row.metadata ?? undefined,
  };
}

function toDecision(row: DecisionRow): FindingDecision {
  return {
    id: row.id,
    findingId: row.finding_id,
    fromStatus: row.from_status as FindingDecision["fromStatus"],
    toStatus: row.to_status as FindingDecision["toStatus"],
    reason: undef(row.reason),
    decidedBy: row.decided_by,
    decidedAt: row.decided_at.toISOString(),
  };
}

function toParams(finding: SecurityFinding): unknown[] {
  return [
    finding.fingerprint,
    finding.id,
    finding.scanner,
    finding.category,
    finding.severity,
    finding.title,
    finding.description ?? null,
    finding.repositoryId ?? null,
    finding.repositoryName ?? null,
    finding.branch ?? null,
    finding.commitSha ?? null,
    finding.applicationId ?? null,
    finding.environment ?? null,
    finding.file ?? null,
    finding.startLine ?? null,
    finding.endLine ?? null,
    finding.packageName ?? null,
    finding.packageVersion ?? null,
    finding.fixedVersion ?? null,
    finding.cve ?? null,
    finding.cwe ?? null,
    finding.ruleId ?? null,
    finding.resource ?? null,
    finding.azureResourceId ?? null,
    finding.subscriptionId ?? null,
    finding.resourceGroup ?? null,
    finding.status,
    finding.firstDetectedAt,
    finding.lastDetectedAt,
    finding.resolvedAt ?? null,
    finding.statusReason ?? null,
    finding.statusChangedAt ?? null,
    finding.statusChangedBy ?? null,
    finding.remediation ?? null,
    finding.sourceUrl ?? null,
    finding.metadata ? JSON.stringify(finding.metadata) : null,
  ];
}

/**
 * Postgres caps a statement at 65535 bound parameters. At 36 columns per row
 * that is ~1820 rows; chunk well below it so a large Trivy image report cannot
 * fail on batch size alone.
 */
const MAX_ROWS_PER_INSERT = 500;

/** Surface retries as telemetry. Counts and labels only — never SQL or rows. */
function reportRetry(info: {
  attempt: number;
  delayMs: number;
  operation?: string;
}): void {
  recordSecurityEvent("db.query.retry", {
    operation: info.operation,
    attempt: info.attempt,
    delayMs: info.delayMs,
  });
}

export class PostgresSecurityFindingRepository
  implements SecurityFindingRepository
{
  constructor(private readonly pool: Pool = getPool()) {}

  /**
   * Single-statement query with transient-failure retry.
   *
   * Safe to retry unconditionally: there is no open transaction here, and every
   * statement issued through this path is either a read or an idempotent
   * upsert. Multi-statement transactions retry as a whole unit instead — see
   * `saveMany`.
   */
  private async query<T>(
    text: string,
    params: readonly unknown[] = [],
    operation = "findings.query",
  ): Promise<T[]> {
    return withRetry(
      async () => {
        const result = await this.pool.query(text, params as unknown[]);
        return result.rows as T[];
      },
      { operation, onRetry: reportRetry },
    );
  }

  // --- reads ---------------------------------------------------------------

  async findAll(query: FindingQuery = {}): Promise<Page<SecurityFinding>> {
    const countBuilder = new ParamBuilder();
    const countWhere = buildWhereClause(query, countBuilder);
    const [{ count }] = await this.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM security_findings f ${countWhere}`,
      countBuilder.params(),
    );

    const total = Number(count);
    const pageSize = clampPageSize(query.pageSize);
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    // Clamp rather than return an empty page for an out-of-range request,
    // matching the in-memory behaviour.
    const page = clamp(query.page ?? 1, 1, totalPages);

    const builder = new ParamBuilder();
    const where = buildWhereClause(query, builder);
    const orderBy = buildOrderByClause(query.sortBy, query.sortDirection);
    const limit = builder.add(pageSize);
    const offset = builder.add((page - 1) * pageSize);

    const rows = await this.query<FindingRow>(
      `SELECT ${COLUMNS} FROM security_findings f ${where} ${orderBy} LIMIT ${limit} OFFSET ${offset}`,
      builder.params(),
    );

    return {
      items: rows.map(toFinding),
      total,
      page,
      pageSize,
      totalPages,
    };
  }

  async findById(id: string): Promise<SecurityFinding | null> {
    const rows = await this.query<FindingRow>(
      `SELECT ${COLUMNS} FROM security_findings f WHERE f.id = $1`,
      [id],
    );
    return rows[0] ? toFinding(rows[0]) : null;
  }

  async findByFingerprint(fingerprint: string): Promise<SecurityFinding | null> {
    const rows = await this.query<FindingRow>(
      `SELECT ${COLUMNS} FROM security_findings f WHERE f.fingerprint = $1`,
      [fingerprint],
    );
    return rows[0] ? toFinding(rows[0]) : null;
  }

  async findManyByFingerprints(
    fingerprints: readonly string[],
  ): Promise<Map<string, SecurityFinding>> {
    if (fingerprints.length === 0) return new Map();

    const rows = await this.query<FindingRow>(
      `SELECT ${COLUMNS} FROM security_findings f WHERE f.fingerprint = ANY($1::text[])`,
      [[...fingerprints]],
    );

    return new Map(rows.map((row) => [row.fingerprint, toFinding(row)]));
  }

  async findByScope(scope: ResolutionScope): Promise<SecurityFinding[]> {
    // Mirrors the in-memory scope rule: prefer repositoryId when either side
    // has one, otherwise fall back to repositoryName.
    const useId = Boolean(scope.repositoryId);
    const rows = await this.query<FindingRow>(
      `SELECT ${COLUMNS} FROM security_findings f
       WHERE f.scanner = $1
         AND ${useId ? "f.repository_id IS NOT DISTINCT FROM $2" : "(f.repository_id IS NULL AND f.repository_name IS NOT DISTINCT FROM $2)"}`,
      [scope.scanner, useId ? scope.repositoryId : (scope.repositoryName ?? null)],
    );
    return rows.map(toFinding);
  }

  async count(filters: FindingFilters = {}): Promise<number> {
    const builder = new ParamBuilder();
    const where = buildWhereClause(filters, builder);
    const [{ count }] = await this.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM security_findings f ${where}`,
      builder.params(),
    );
    return Number(count);
  }

  // --- writes --------------------------------------------------------------

  async save(finding: SecurityFinding): Promise<SecurityFinding> {
    await this.saveMany([finding]);
    return finding;
  }

  async saveMany(
    findings: readonly SecurityFinding[],
  ): Promise<SecurityFinding[]> {
    if (findings.length === 0) return [];

    // Retried as one unit, from BEGIN: a connection lost mid-transaction leaves
    // the server-side transaction aborted, so replaying individual statements
    // would fail. Replaying the whole batch is safe because the INSERT is an
    // idempotent upsert on `fingerprint`.
    return withRetry(() => this.saveManyOnce(findings), {
      operation: "findings.saveMany",
      onRetry: reportRetry,
    });
  }

  private async saveManyOnce(
    findings: readonly SecurityFinding[],
  ): Promise<SecurityFinding[]> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");

      for (let start = 0; start < findings.length; start += MAX_ROWS_PER_INSERT) {
        const chunk = findings.slice(start, start + MAX_ROWS_PER_INSERT);

        const values: unknown[] = [];
        const tuples = chunk.map((finding, rowIndex) => {
          const params = toParams(finding);
          values.push(...params);
          const placeholders = params.map(
            (_, columnIndex) =>
              `$${rowIndex * COLUMN_COUNT + columnIndex + 1}`,
          );
          return `(${placeholders.join(", ")})`;
        });

        // The reconciled finding is authoritative: lifecycle merging already
        // happened in the service, so every column is overwritten.
        await client.query(
          `INSERT INTO security_findings (${COLUMNS}) VALUES ${tuples.join(", ")}
           ON CONFLICT (fingerprint) DO UPDATE SET
             scanner = EXCLUDED.scanner,
             category = EXCLUDED.category,
             severity = EXCLUDED.severity,
             title = EXCLUDED.title,
             description = EXCLUDED.description,
             repository_id = EXCLUDED.repository_id,
             repository_name = EXCLUDED.repository_name,
             branch = EXCLUDED.branch,
             commit_sha = EXCLUDED.commit_sha,
             application_id = EXCLUDED.application_id,
             environment = EXCLUDED.environment,
             file = EXCLUDED.file,
             start_line = EXCLUDED.start_line,
             end_line = EXCLUDED.end_line,
             package_name = EXCLUDED.package_name,
             package_version = EXCLUDED.package_version,
             fixed_version = EXCLUDED.fixed_version,
             cve = EXCLUDED.cve,
             cwe = EXCLUDED.cwe,
             rule_id = EXCLUDED.rule_id,
             resource = EXCLUDED.resource,
             azure_resource_id = EXCLUDED.azure_resource_id,
             subscription_id = EXCLUDED.subscription_id,
             resource_group = EXCLUDED.resource_group,
             status = EXCLUDED.status,
             first_detected_at = EXCLUDED.first_detected_at,
             last_detected_at = EXCLUDED.last_detected_at,
             resolved_at = EXCLUDED.resolved_at,
             status_reason = EXCLUDED.status_reason,
             status_changed_at = EXCLUDED.status_changed_at,
             status_changed_by = EXCLUDED.status_changed_by,
             remediation = EXCLUDED.remediation,
             source_url = EXCLUDED.source_url,
             metadata = EXCLUDED.metadata`,
          values,
        );
      }

      await client.query("COMMIT");
      return [...findings];
    } catch (error) {
      // A rollback on an already-dead connection throws again; the original
      // error is what matters, so the attempt is best-effort.
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async update(
    id: string,
    patch: Partial<SecurityFinding>,
  ): Promise<SecurityFinding | null> {
    const existing = await this.findById(id);
    if (!existing) return null;

    // Identity is not patchable — changing it would orphan history.
    const { id: _id, fingerprint: _fingerprint, ...safePatch } = patch;
    void _id;
    void _fingerprint;

    const updated: SecurityFinding = { ...existing, ...safePatch };
    await this.saveMany([updated]);
    return updated;
  }

  async recordDecision(
    id: string,
    patch: Partial<SecurityFinding>,
    decision: FindingDecision,
  ): Promise<SecurityFinding | null> {
    // Retried as one unit, from BEGIN, like saveMany. The replay hazard is the
    // decision INSERT — an append is not naturally idempotent — so it dedupes
    // on the service-generated id.
    return withRetry(() => this.recordDecisionOnce(id, patch, decision), {
      operation: "findings.recordDecision",
      onRetry: reportRetry,
    });
  }

  private async recordDecisionOnce(
    id: string,
    patch: Partial<SecurityFinding>,
    decision: FindingDecision,
  ): Promise<SecurityFinding | null> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");

      const found = await client.query(
        `SELECT ${COLUMNS} FROM security_findings f WHERE f.id = $1`,
        [id],
      );
      const row = found.rows[0] as FindingRow | undefined;
      if (!row) {
        await client.query("ROLLBACK");
        return null;
      }

      // Identity is not patchable — changing it would orphan history.
      const { id: _id, fingerprint: _fingerprint, ...safePatch } = patch;
      void _id;
      void _fingerprint;
      const updated: SecurityFinding = { ...toFinding(row), ...safePatch };

      // Full-column overwrite, mirroring saveMany: the merged finding is
      // authoritative. Params follow the COLUMNS order; $2 is the id.
      const result = await client.query(
        `UPDATE security_findings SET
           fingerprint = $1, scanner = $3, category = $4, severity = $5,
           title = $6, description = $7, repository_id = $8,
           repository_name = $9, branch = $10, commit_sha = $11,
           application_id = $12, environment = $13, file = $14,
           start_line = $15, end_line = $16, package_name = $17,
           package_version = $18, fixed_version = $19, cve = $20, cwe = $21,
           rule_id = $22, resource = $23, azure_resource_id = $24,
           subscription_id = $25, resource_group = $26, status = $27,
           first_detected_at = $28, last_detected_at = $29, resolved_at = $30,
           status_reason = $31, status_changed_at = $32,
           status_changed_by = $33, remediation = $34, source_url = $35,
           metadata = $36
         WHERE id = $2`,
        toParams(updated),
      );
      if (result.rowCount === 0) {
        // Findings are never deleted, so this cannot happen today; stated so
        // the atomicity guarantee does not depend on that staying true.
        await client.query("ROLLBACK");
        return null;
      }

      // ON CONFLICT DO NOTHING: a retry that replays a transaction whose
      // COMMIT acknowledgement was lost must not append a second row.
      await client.query(
        `INSERT INTO finding_decisions
           (id, finding_id, from_status, to_status, reason, decided_by, decided_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (id) DO NOTHING`,
        [
          decision.id,
          decision.findingId,
          decision.fromStatus,
          decision.toStatus,
          decision.reason ?? null,
          decision.decidedBy,
          decision.decidedAt,
        ],
      );

      await client.query("COMMIT");
      return updated;
    } catch (error) {
      // A rollback on an already-dead connection throws again; the original
      // error is what matters, so the attempt is best-effort.
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async listDecisionHistory(id: string): Promise<FindingDecision[]> {
    const rows = await this.query<DecisionRow>(
      `SELECT id, finding_id, from_status, to_status, reason, decided_by, decided_at
       FROM finding_decisions
       WHERE finding_id = $1
       ORDER BY decided_at DESC, id DESC`,
      [id],
    );
    return rows.map(toDecision);
  }

  // --- aggregates ----------------------------------------------------------

  async getStatistics(
    filters: FindingFilters = {},
    window: StatisticsWindow = {},
  ): Promise<FindingStatistics> {
    const builder = new ParamBuilder();
    const where = buildWhereClause(filters, builder);

    const from = window.from ? new Date(window.from).toISOString() : null;
    const to = window.to
      ? new Date(window.to).toISOString()
      : new Date().toISOString();

    const fromParam = builder.add(from);
    const toParam = builder.add(to);

    const inWindow = (column: string) =>
      `(${fromParam}::timestamptz IS NULL OR ${column} >= ${fromParam}::timestamptz) AND ${column} <= ${toParam}::timestamptz`;

    const [totals] = await this.query<{
      total: string;
      open: string;
      resolved: string;
      accepted: string;
      false_positive: string;
      suppressed: string;
      new_findings: string;
      resolved_in_window: string;
      mttr_hours: string | null;
    }>(
      `SELECT
         COUNT(*)::text AS total,
         COUNT(*) FILTER (WHERE f.status = 'OPEN')::text AS open,
         COUNT(*) FILTER (WHERE f.status = 'RESOLVED')::text AS resolved,
         COUNT(*) FILTER (WHERE f.status = 'ACCEPTED_RISK')::text AS accepted,
         COUNT(*) FILTER (WHERE f.status = 'FALSE_POSITIVE')::text AS false_positive,
         COUNT(*) FILTER (WHERE f.status = 'SUPPRESSED')::text AS suppressed,
         COUNT(*) FILTER (WHERE ${inWindow("f.first_detected_at")})::text AS new_findings,
         COUNT(*) FILTER (WHERE f.resolved_at IS NOT NULL AND ${inWindow("f.resolved_at")})::text AS resolved_in_window,
         AVG(EXTRACT(EPOCH FROM (f.resolved_at - f.first_detected_at)) / 3600.0)
           FILTER (
             WHERE f.resolved_at IS NOT NULL
               AND ${inWindow("f.resolved_at")}
               AND f.resolved_at >= f.first_detected_at
           )::text AS mttr_hours
       FROM security_findings f ${where}`,
      builder.params(),
    );

    // Breakdowns describe CURRENT RISK, so they count open findings only.
    const breakdownBuilder = new ParamBuilder();
    const breakdownWhere = buildWhereClause(filters, breakdownBuilder);
    const openCondition = breakdownWhere
      ? `${breakdownWhere} AND f.status = 'OPEN'`
      : `WHERE f.status = 'OPEN'`;

    const breakdownRows = await this.query<{
      dim: string;
      key: string;
      count: string;
    }>(
      `WITH open_findings AS (
         SELECT f.* FROM security_findings f ${openCondition}
       )
       SELECT 'severity' AS dim, severity AS key, COUNT(*)::text AS count FROM open_findings GROUP BY severity
       UNION ALL
       SELECT 'scanner', scanner, COUNT(*)::text FROM open_findings GROUP BY scanner
       UNION ALL
       SELECT 'category', category, COUNT(*)::text FROM open_findings GROUP BY category
       UNION ALL
       SELECT 'repository', COALESCE(repository_name, 'unassigned'), COUNT(*)::text FROM open_findings GROUP BY COALESCE(repository_name, 'unassigned')
       UNION ALL
       SELECT 'environment', COALESCE(environment, 'unassigned'), COUNT(*)::text FROM open_findings GROUP BY COALESCE(environment, 'unassigned')`,
      breakdownBuilder.params(),
    );

    const bySeverity = emptySeverityCounts();
    const byScanner: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    const byRepository: Record<string, number> = {};
    const byEnvironment: Record<string, number> = {};

    for (const row of breakdownRows) {
      const value = Number(row.count);
      switch (row.dim) {
        case "severity":
          bySeverity[row.key as Severity] = value;
          break;
        case "scanner":
          byScanner[row.key] = value;
          break;
        case "category":
          byCategory[row.key] = value;
          break;
        case "repository":
          byRepository[row.key] = value;
          break;
        case "environment":
          byEnvironment[row.key] = value;
          break;
      }
    }

    const mttr =
      totals.mttr_hours === null ? undefined : Number(totals.mttr_hours);

    return {
      total: Number(totals.total),
      totalOpen: Number(totals.open),
      totalResolved: Number(totals.resolved),
      totalAcceptedRisk: Number(totals.accepted),
      totalFalsePositive: Number(totals.false_positive),
      totalSuppressed: Number(totals.suppressed),
      bySeverity,
      byScanner,
      byCategory,
      byRepository,
      byEnvironment,
      newFindings: Number(totals.new_findings),
      resolvedFindings: Number(totals.resolved_in_window),
      // Undefined when nothing resolved — zero would read as "instant fix".
      meanTimeToRemediateHours:
        mttr === undefined || Number.isNaN(mttr)
          ? undefined
          : Math.round(mttr * 10) / 10,
    };
  }

  async getTrend(
    days: number,
    filters: FindingFilters = {},
    now: Date = new Date(),
  ): Promise<TrendPoint[]> {
    const builder = new ParamBuilder();
    const where = buildWhereClause(filters, builder);
    // Day boundaries are computed in JS and passed in, so both repository
    // implementations bucket by exactly the same UTC midnights.
    const daysParam = builder.add(utcDayStarts(days, now));

    const rows = await this.query<{
      date: string;
      open: string;
      new_count: string;
      resolved: string;
    }>(
      `WITH filtered AS (
         SELECT f.first_detected_at, f.resolved_at FROM security_findings f ${where}
       ),
       days AS (
         SELECT unnest(${daysParam}::timestamptz[]) AS day_start
       )
       SELECT
         to_char(d.day_start AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS date,
         COUNT(f.*) FILTER (
           WHERE f.first_detected_at < d.day_start + interval '1 day'
             AND (f.resolved_at IS NULL OR f.resolved_at >= d.day_start + interval '1 day')
         )::text AS open,
         COUNT(f.*) FILTER (
           WHERE f.first_detected_at >= d.day_start
             AND f.first_detected_at < d.day_start + interval '1 day'
         )::text AS new_count,
         COUNT(f.*) FILTER (
           WHERE f.resolved_at >= d.day_start
             AND f.resolved_at < d.day_start + interval '1 day'
         )::text AS resolved
       FROM days d
       LEFT JOIN filtered f ON true
       GROUP BY d.day_start
       ORDER BY d.day_start`,
      builder.params(),
    );

    return rows.map((row) => ({
      date: row.date,
      open: Number(row.open),
      new: Number(row.new_count),
      resolved: Number(row.resolved),
    }));
  }

  async getRepositorySummaries(
    filters: FindingFilters = {},
  ): Promise<RepositorySecuritySummary[]> {
    const builder = new ParamBuilder();
    const where = buildWhereClause(filters, builder);

    const rows = await this.query<{
      repository_name: string;
      repository_id: string | null;
      severity: string | null;
      scanner: string | null;
      open_count: string;
    }>(
      `WITH filtered AS (SELECT f.* FROM security_findings f ${where})
       SELECT
         COALESCE(repository_name, 'unassigned') AS repository_name,
         MIN(repository_id) AS repository_id,
         severity,
         scanner,
         COUNT(*) FILTER (WHERE status = 'OPEN')::text AS open_count
       FROM filtered
       GROUP BY COALESCE(repository_name, 'unassigned'), severity, scanner`,
      builder.params(),
    );

    const summaries = new Map<string, RepositorySecuritySummary>();

    for (const row of rows) {
      const key = row.repository_name;
      const summary =
        summaries.get(key) ??
        ({
          repositoryName: key,
          repositoryId: undef(row.repository_id),
          openFindings: 0,
          bySeverity: emptySeverityCounts(),
          scanners: [],
        } satisfies RepositorySecuritySummary);

      const openCount = Number(row.open_count);
      summary.openFindings += openCount;
      if (row.severity) {
        summary.bySeverity[row.severity as Severity] += openCount;
      }

      if (row.scanner) {
        const scanner = row.scanner as ScannerType;
        const existing = summary.scanners.find(
          (entry) => entry.scanner === scanner,
        );
        if (existing) {
          existing.openFindings += openCount;
        } else {
          summary.scanners.push({
            scanner,
            status: "PASSED",
            openFindings: openCount,
          });
        }
      }

      summary.repositoryId ??= undef(row.repository_id);
      summaries.set(key, summary);
    }

    // A scanner with open findings failed its gate — resolved after
    // aggregation because a scanner can contribute several severity rows.
    for (const summary of summaries.values()) {
      summary.scanners = summary.scanners.map((entry) => ({
        ...entry,
        status: entry.openFindings > 0 ? "FAILED" : "PASSED",
      }));
    }

    return [...summaries.values()].sort(
      (a, b) => b.openFindings - a.openFindings,
    );
  }

  async listFilterOptions(): Promise<FilterOptions> {
    const rows = await this.query<{ dim: string; value: string }>(
      `SELECT 'repository' AS dim, repository_name AS value FROM security_findings WHERE repository_name IS NOT NULL
       UNION
       SELECT 'environment', environment FROM security_findings WHERE environment IS NOT NULL
       UNION
       SELECT 'scanner', scanner FROM security_findings
       UNION
       SELECT 'category', category FROM security_findings`,
    );

    const collect = (dim: string) =>
      rows
        .filter((row) => row.dim === dim)
        .map((row) => row.value)
        .sort();

    return {
      repositories: collect("repository"),
      environments: collect("environment"),
      scanners: collect("scanner"),
      categories: collect("category"),
    };
  }

  /** Test helper: remove every row. Never called by application code. */
  async truncate(): Promise<void> {
    // CASCADE: finding_decisions references this table.
    await this.query("TRUNCATE security_findings CASCADE");
  }
}
