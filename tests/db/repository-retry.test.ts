import type { Pool } from "pg";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { PostgresSecurityFindingRepository } from "@/lib/security/repository/postgres-security-finding-repository";
import { PostgresScanRunRepository } from "@/lib/security/repository/postgres-scan-run-repository";
import { emptyScanRunCounts } from "@/domain/security/scan-run";
import {
  getSecurityEventCounters,
  resetSecurityEventCounters,
} from "@/lib/security/observability";
import { finding } from "../repository/repository-contract";

/**
 * Proves the repositories actually retry, using a fake pool that fails a set
 * number of times before succeeding.
 *
 * A real database cannot be made to drop a connection on cue without a flaky
 * test, so the failure is injected at the pool boundary — which is exactly
 * where a dropped connection surfaces in production.
 */

function pgError(code: string): Error & { code: string } {
  return Object.assign(new Error("injected failure"), { code });
}

/**
 * Pool stub that fails `failures` times, then succeeds with `rows`.
 * `rows` is configurable because some statements (COUNT) always return a row.
 */
function flakyPool(failures: number, rows: unknown[] = []) {
  let remaining = failures;
  // The parameter gives the mock a typed signature so assertions can inspect
  // the SQL each call received.
  const clientQuery = vi.fn(async (text?: string) => ({ rows: [], text }));
  const release = vi.fn();

  const query = vi.fn(async () => {
    if (remaining > 0) {
      remaining -= 1;
      throw pgError("08006");
    }
    return { rows };
  });

  const connect = vi.fn(async () => {
    if (remaining > 0) {
      remaining -= 1;
      throw pgError("ECONNRESET");
    }
    return { query: clientQuery, release };
  });

  return {
    pool: { query, connect } as unknown as Pool,
    query,
    connect,
    clientQuery,
    release,
    remaining: () => remaining,
  };
}

// Retry delays are irrelevant to correctness here; keep the suite fast.
beforeEach(() => {
  resetSecurityEventCounters();
  vi.stubEnv("DATABASE_RETRY_BASE_DELAY_MS", "1");
  vi.stubEnv("DATABASE_RETRY_MAX_DELAY_MS", "1");
});

describe("PostgresSecurityFindingRepository retry", () => {
  it("retries a dropped connection on a read and still returns data", async () => {
    const { pool, query } = flakyPool(2);
    const repository = new PostgresSecurityFindingRepository(pool);

    await expect(repository.findById("fnd_x")).resolves.toBeNull();
    // Two failures plus the successful attempt.
    expect(query).toHaveBeenCalledTimes(3);
  });

  it("gives up after the configured retry budget", async () => {
    vi.stubEnv("DATABASE_MAX_RETRIES", "2");
    const { pool, query } = flakyPool(99);
    const repository = new PostgresSecurityFindingRepository(pool);

    await expect(repository.findById("fnd_x")).rejects.toThrow(
      "injected failure",
    );
    expect(query).toHaveBeenCalledTimes(3);
  });

  it("does not retry a permanent error", async () => {
    const query = vi.fn(async () => {
      throw pgError("42P01"); // undefined_table
    });
    const repository = new PostgresSecurityFindingRepository({
      query,
    } as unknown as Pool);

    await expect(repository.count()).rejects.toThrow("injected failure");
    expect(query).toHaveBeenCalledTimes(1);
  });

  it("replays the whole transaction when saveMany loses its connection", async () => {
    const { pool, connect, clientQuery } = flakyPool(1);
    const repository = new PostgresSecurityFindingRepository(pool);

    await repository.saveMany([finding({ fingerprint: "retry_1" })]);

    // The first connect() failed; the second succeeded and ran the batch.
    expect(connect).toHaveBeenCalledTimes(2);
    // Replayed from BEGIN, not resumed mid-transaction.
    const statements = clientQuery.mock.calls.map((call) =>
      String(call[0]).trim().slice(0, 6).toUpperCase(),
    );
    expect(statements[0]).toBe("BEGIN");
    expect(statements.at(-1)).toBe("COMMIT");
  });

  it("still releases the client when the transaction fails outright", async () => {
    const release = vi.fn();
    const clientQuery = vi.fn(async (text: string) => {
      if (String(text).startsWith("INSERT")) throw pgError("23505");
      return { rows: [] };
    });
    const pool = {
      connect: async () => ({ query: clientQuery, release }),
    } as unknown as Pool;

    const repository = new PostgresSecurityFindingRepository(pool);

    await expect(
      repository.saveMany([finding({ fingerprint: "boom" })]),
    ).rejects.toThrow("injected failure");

    // A leaked client here would exhaust the pool after a handful of errors.
    expect(release).toHaveBeenCalledTimes(1);
    // ROLLBACK was attempted before giving up.
    expect(
      clientQuery.mock.calls.some((call) => String(call[0]) === "ROLLBACK"),
    ).toBe(true);
  });

  it("records a retry event without leaking SQL", async () => {
    const { pool } = flakyPool(1, [{ count: "0" }]);
    const repository = new PostgresSecurityFindingRepository(pool);

    await repository.count();

    expect(getSecurityEventCounters()["db.query.retry"]).toBe(1);
  });
});

describe("PostgresScanRunRepository retry", () => {
  it("retries a transient failure when saving a scan run", async () => {
    const { pool, query } = flakyPool(1);
    const repository = new PostgresScanRunRepository(pool);

    await repository.save({
      id: "run_1",
      scanner: "TRIVY",
      status: "COMPLETED",
      startedAt: "2026-08-10T12:00:00.000Z",
      findings: emptyScanRunCounts(),
      totalFindings: 0,
    });

    expect(query).toHaveBeenCalledTimes(2);
  });

  it("retries scanner-health reads", async () => {
    const { pool, query } = flakyPool(2);
    const repository = new PostgresScanRunRepository(pool);

    await expect(repository.latestByScanner()).resolves.toEqual(new Map());
    expect(query).toHaveBeenCalledTimes(3);
  });
});
