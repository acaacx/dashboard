import type { FindingFilters, FindingQuery } from "@/domain/security/finding";

/**
 * SQL fragment builders.
 *
 * Pure functions, deliberately separated from the repository so the query logic
 * is unit-testable without a database. Every user-supplied value becomes a
 * bound parameter — there is no string interpolation of input anywhere in this
 * file, which is what keeps the filter surface free of injection.
 */

/** Accumulates bound parameters and hands back their placeholders. */
export class ParamBuilder {
  private readonly values: unknown[] = [];

  add(value: unknown): string {
    this.values.push(value);
    return `$${this.values.length}`;
  }

  params(): unknown[] {
    return [...this.values];
  }

  get length(): number {
    return this.values.length;
  }
}

/**
 * Severity ordering as SQL. Mirrors SEVERITY_RANK in the domain enums; a
 * mismatch here would make the two repository implementations sort differently.
 */
export const SEVERITY_RANK_SQL = `CASE f.severity
  WHEN 'CRITICAL' THEN 5
  WHEN 'HIGH' THEN 4
  WHEN 'MEDIUM' THEN 3
  WHEN 'LOW' THEN 2
  WHEN 'INFO' THEN 1
  ELSE 0
END`;

/** Columns the free-text search covers — identical to the in-memory store. */
const SEARCH_COLUMNS = [
  "f.title",
  "f.cve",
  "f.cwe",
  "f.repository_name",
  "f.file",
  "f.resource",
  "f.rule_id",
  "f.package_name",
  "f.azure_resource_id",
] as const;

/**
 * Escape LIKE metacharacters so a search for "100%" or "a_b" is treated as
 * literal text, matching JavaScript's `String.includes` semantics.
 */
export function escapeLikePattern(value: string): string {
  return value.replace(/([\\%_])/g, "\\$1");
}

/**
 * Build the WHERE conditions for a filter set.
 * Returns the conditions only (no `WHERE` keyword) so callers can compose.
 */
export function buildFindingConditions(
  filters: FindingFilters,
  builder: ParamBuilder,
): string[] {
  const conditions: string[] = [];

  const inFilter = (column: string, values: readonly string[] | undefined) => {
    if (!values || values.length === 0) return;
    conditions.push(`${column} = ANY(${builder.add([...values])}::text[])`);
  };

  inFilter("f.severity", filters.severity);
  inFilter("f.scanner", filters.scanner);
  inFilter("f.category", filters.category);
  inFilter("f.status", filters.status);

  // A repository or environment filter must exclude rows where the column is
  // NULL, matching the in-memory implementation, which requires the finding to
  // actually carry the value.
  if (filters.repository?.length) {
    conditions.push(
      `(f.repository_name IS NOT NULL AND f.repository_name = ANY(${builder.add(
        [...filters.repository],
      )}::text[]))`,
    );
  }

  if (filters.environment?.length) {
    conditions.push(
      `(f.environment IS NOT NULL AND f.environment = ANY(${builder.add(
        [...filters.environment],
      )}::text[]))`,
    );
  }

  if (filters.detectedSince) {
    const since = Date.parse(filters.detectedSince);
    if (Number.isFinite(since)) {
      conditions.push(
        `f.last_detected_at >= ${builder.add(new Date(since).toISOString())}::timestamptz`,
      );
    }
  }

  const search = filters.search?.trim();
  if (search) {
    const placeholder = builder.add(`%${escapeLikePattern(search)}%`);
    const clauses = SEARCH_COLUMNS.map(
      (column) => `${column} ILIKE ${placeholder} ESCAPE '\\'`,
    );
    conditions.push(`(${clauses.join(" OR ")})`);
  }

  return conditions;
}

/** `WHERE ...` or an empty string when nothing is filtered. */
export function buildWhereClause(
  filters: FindingFilters,
  builder: ParamBuilder,
): string {
  const conditions = buildFindingConditions(filters, builder);
  return conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
}

const SORT_COLUMN: Record<
  NonNullable<FindingQuery["sortBy"]>,
  string
> = {
  severity: SEVERITY_RANK_SQL,
  title: "f.title",
  firstDetectedAt: "f.first_detected_at",
  lastDetectedAt: "f.last_detected_at",
};

/**
 * ORDER BY with the same tiebreak chain as the in-memory sort: primary key,
 * then severity descending, then most recently seen, then id.
 */
export function buildOrderByClause(
  sortBy: NonNullable<FindingQuery["sortBy"]> = "severity",
  direction: "asc" | "desc" = "desc",
): string {
  const column = SORT_COLUMN[sortBy] ?? SEVERITY_RANK_SQL;
  const primaryDirection = direction === "asc" ? "ASC" : "DESC";

  return [
    `ORDER BY ${column} ${primaryDirection}`,
    `${SEVERITY_RANK_SQL} DESC`,
    "f.last_detected_at DESC",
    "f.id ASC",
  ].join(", ");
}

export function clampPageSize(pageSize: number | undefined): number {
  return clamp(pageSize ?? 25, 1, 200);
}

export function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(Math.max(Math.trunc(value), min), max);
}

/** UTC midnight timestamps for the last `days` days, oldest first. */
export function utcDayStarts(days: number, now: Date): string[] {
  const dayCount = clamp(days, 1, 365);
  const today = Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate(),
  );

  const starts: string[] = [];
  for (let offset = dayCount - 1; offset >= 0; offset -= 1) {
    starts.push(new Date(today - offset * 86_400_000).toISOString());
  }
  return starts;
}
