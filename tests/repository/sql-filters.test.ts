import { describe, expect, it } from "vitest";

import {
  buildFindingConditions,
  buildOrderByClause,
  buildWhereClause,
  clamp,
  clampPageSize,
  escapeLikePattern,
  ParamBuilder,
  utcDayStarts,
} from "@/lib/security/repository/postgres/sql-filters";

/**
 * The SQL builders are pure, so they are tested without a database. The
 * database-backed behaviour they produce is covered separately by the
 * repository contract suite.
 */

describe("ParamBuilder", () => {
  it("numbers placeholders from one and preserves order", () => {
    const builder = new ParamBuilder();
    expect(builder.add("a")).toBe("$1");
    expect(builder.add(2)).toBe("$2");
    expect(builder.params()).toEqual(["a", 2]);
  });
});

describe("buildFindingConditions", () => {
  it("returns nothing for an empty filter set", () => {
    const builder = new ParamBuilder();
    expect(buildFindingConditions({}, builder)).toEqual([]);
    expect(buildWhereClause({}, builder)).toBe("");
  });

  it("ignores empty arrays", () => {
    const builder = new ParamBuilder();
    expect(
      buildFindingConditions({ severity: [], scanner: [], status: [] }, builder),
    ).toEqual([]);
    expect(builder.length).toBe(0);
  });

  it("binds every value rather than interpolating it", () => {
    const builder = new ParamBuilder();
    const where = buildWhereClause(
      { severity: ["CRITICAL"], search: "'; DROP TABLE security_findings; --" },
      builder,
    );

    // The injection attempt exists only as a bound parameter.
    expect(where).not.toContain("DROP TABLE");
    expect(builder.params()).toContainEqual(
      "%'; DROP TABLE security\\_findings; --%",
    );
    expect(where).toMatch(/\$\d+/);
  });

  it("requires a non-null column when repository or environment is filtered", () => {
    const builder = new ParamBuilder();
    const where = buildWhereClause(
      { repository: ["payment-service"], environment: ["production"] },
      builder,
    );

    expect(where).toContain("f.repository_name IS NOT NULL");
    expect(where).toContain("f.environment IS NOT NULL");
  });

  it("covers exactly the documented search columns", () => {
    const builder = new ParamBuilder();
    const where = buildWhereClause({ search: "abc" }, builder);

    for (const column of [
      "f.title",
      "f.cve",
      "f.cwe",
      "f.repository_name",
      "f.file",
      "f.resource",
      "f.rule_id",
      "f.package_name",
      "f.azure_resource_id",
    ]) {
      expect(where).toContain(`${column} ILIKE`);
    }
  });

  it("skips an unparseable detectedSince instead of emitting broken SQL", () => {
    const builder = new ParamBuilder();
    expect(buildFindingConditions({ detectedSince: "not-a-date" }, builder)).toEqual(
      [],
    );
  });

  it("ignores a whitespace-only search", () => {
    const builder = new ParamBuilder();
    expect(buildFindingConditions({ search: "   " }, builder)).toEqual([]);
  });
});

describe("escapeLikePattern", () => {
  it("escapes LIKE metacharacters so they match literally", () => {
    expect(escapeLikePattern("100%")).toBe("100\\%");
    expect(escapeLikePattern("a_b")).toBe("a\\_b");
    expect(escapeLikePattern("back\\slash")).toBe("back\\\\slash");
    expect(escapeLikePattern("plain")).toBe("plain");
  });
});

describe("buildOrderByClause", () => {
  it("defaults to severity descending", () => {
    const clause = buildOrderByClause();
    expect(clause.startsWith("ORDER BY CASE f.severity")).toBe(true);
    expect(clause).toContain("DESC");
  });

  it("supports ascending order", () => {
    expect(buildOrderByClause("title", "asc")).toContain("f.title ASC");
  });

  it("always appends the same tiebreak chain", () => {
    const clause = buildOrderByClause("firstDetectedAt", "asc");
    expect(clause).toContain("f.first_detected_at ASC");
    expect(clause).toContain("f.last_detected_at DESC");
    expect(clause.endsWith("f.id ASC")).toBe(true);
  });
});

describe("clamp helpers", () => {
  it("bounds page size", () => {
    expect(clampPageSize(undefined)).toBe(25);
    expect(clampPageSize(0)).toBe(1);
    expect(clampPageSize(5000)).toBe(200);
    expect(clampPageSize(Number.NaN)).toBe(1);
  });

  it("bounds arbitrary values", () => {
    expect(clamp(5, 1, 10)).toBe(5);
    expect(clamp(-3, 1, 10)).toBe(1);
    expect(clamp(99, 1, 10)).toBe(10);
  });
});

describe("utcDayStarts", () => {
  it("returns UTC midnights, oldest first, ending today", () => {
    const days = utcDayStarts(3, new Date("2026-08-10T18:42:11.000Z"));
    expect(days).toEqual([
      "2026-08-08T00:00:00.000Z",
      "2026-08-09T00:00:00.000Z",
      "2026-08-10T00:00:00.000Z",
    ]);
  });

  it("bounds the requested range", () => {
    const now = new Date("2026-08-10T00:00:00.000Z");
    expect(utcDayStarts(0, now)).toHaveLength(1);
    expect(utcDayStarts(9999, now)).toHaveLength(365);
  });
});
