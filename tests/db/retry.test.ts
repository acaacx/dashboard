import { describe, expect, it, vi } from "vitest";

import {
  backoffDelay,
  isRetryableDatabaseError,
  withRetry,
} from "@/lib/db/retry";

/** Build an error shaped like the ones `pg` throws. */
function pgError(code: string, message = "boom"): Error & { code: string } {
  return Object.assign(new Error(message), { code });
}

/** Deterministic sleep + jitter so tests never depend on wall-clock timing. */
const harness = () => {
  const delays: number[] = [];
  return {
    delays,
    sleep: async (ms: number) => {
      delays.push(ms);
    },
    random: () => 1, // full jitter at its maximum -> delay equals the cap
  };
};

describe("isRetryableDatabaseError", () => {
  it("retries connection-class failures", () => {
    for (const code of ["08000", "08001", "08003", "08004", "08006", "08P01"]) {
      expect(isRetryableDatabaseError(pgError(code))).toBe(true);
    }
  });

  it("retries operator intervention and resource exhaustion", () => {
    for (const code of ["57P01", "57P02", "57P03", "53300"]) {
      expect(isRetryableDatabaseError(pgError(code))).toBe(true);
    }
  });

  it("retries lost transaction races", () => {
    expect(isRetryableDatabaseError(pgError("40001"))).toBe(true);
    expect(isRetryableDatabaseError(pgError("40P01"))).toBe(true);
  });

  it("retries socket-level failures", () => {
    for (const code of ["ECONNRESET", "ECONNREFUSED", "EPIPE", "ETIMEDOUT"]) {
      expect(isRetryableDatabaseError(pgError(code))).toBe(true);
    }
  });

  // The important half: retrying these would hide a bug and waste time.
  it("does NOT retry programming or data errors", () => {
    expect(isRetryableDatabaseError(pgError("23505"))).toBe(false); // unique_violation
    expect(isRetryableDatabaseError(pgError("23503"))).toBe(false); // foreign_key_violation
    expect(isRetryableDatabaseError(pgError("42601"))).toBe(false); // syntax_error
    expect(isRetryableDatabaseError(pgError("42P01"))).toBe(false); // undefined_table
    expect(isRetryableDatabaseError(pgError("22P02"))).toBe(false); // invalid_text_representation
  });

  it("matches pool errors that carry no code", () => {
    expect(
      isRetryableDatabaseError(new Error("Connection terminated unexpectedly")),
    ).toBe(true);
    expect(
      isRetryableDatabaseError(
        new Error("timeout exceeded when trying to connect"),
      ),
    ).toBe(true);
    expect(
      isRetryableDatabaseError(
        new Error("the database system is starting up"),
      ),
    ).toBe(true);
  });

  it("does not retry an arbitrary uncoded error", () => {
    expect(isRetryableDatabaseError(new Error("something went wrong"))).toBe(
      false,
    );
    expect(isRetryableDatabaseError(null)).toBe(false);
    expect(isRetryableDatabaseError(undefined)).toBe(false);
    expect(isRetryableDatabaseError("string")).toBe(false);
  });
});

describe("backoffDelay", () => {
  it("grows exponentially and is capped", () => {
    const noJitter = () => 1;
    expect(backoffDelay(0, 100, 2000, noJitter)).toBe(100);
    expect(backoffDelay(1, 100, 2000, noJitter)).toBe(200);
    expect(backoffDelay(2, 100, 2000, noJitter)).toBe(400);
    expect(backoffDelay(10, 100, 2000, noJitter)).toBe(2000);
  });

  it("applies jitter so retries do not synchronise", () => {
    // Full jitter: the delay is anywhere in [0, exponential].
    expect(backoffDelay(3, 100, 2000, () => 0)).toBe(0);
    expect(backoffDelay(3, 100, 2000, () => 0.5)).toBe(400);
    expect(backoffDelay(3, 100, 2000, () => 1)).toBe(800);
  });
});

describe("withRetry", () => {
  it("returns the result without retrying when the call succeeds", async () => {
    const fn = vi.fn().mockResolvedValue("ok");
    const { sleep, random } = harness();

    await expect(withRetry(fn, { sleep, random })).resolves.toBe("ok");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("retries a transient failure and then succeeds", async () => {
    const fn = vi
      .fn()
      .mockRejectedValueOnce(pgError("08006"))
      .mockRejectedValueOnce(pgError("ECONNRESET"))
      .mockResolvedValue("recovered");

    const { sleep, random, delays } = harness();
    await expect(
      withRetry(fn, { sleep, random, baseDelayMs: 100, maxDelayMs: 2000 }),
    ).resolves.toBe("recovered");

    expect(fn).toHaveBeenCalledTimes(3);
    expect(delays).toEqual([100, 200]);
  });

  it("gives up after maxRetries and rethrows the original error", async () => {
    const error = pgError("08006", "connection failure");
    const fn = vi.fn().mockRejectedValue(error);
    const { sleep, random } = harness();

    await expect(
      withRetry(fn, { maxRetries: 2, sleep, random }),
    ).rejects.toBe(error);

    // First attempt plus two retries.
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it("fails immediately on a permanent error", async () => {
    const error = pgError("23505", "duplicate key");
    const fn = vi.fn().mockRejectedValue(error);
    const { sleep, random, delays } = harness();

    await expect(withRetry(fn, { sleep, random })).rejects.toBe(error);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(delays).toEqual([]);
  });

  it("does not retry at all when maxRetries is zero", async () => {
    const fn = vi.fn().mockRejectedValue(pgError("08006"));
    const { sleep, random } = harness();

    await expect(
      withRetry(fn, { maxRetries: 0, sleep, random }),
    ).rejects.toThrow();
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("reports each retry for telemetry", async () => {
    const onRetry = vi.fn();
    const fn = vi
      .fn()
      .mockRejectedValueOnce(pgError("40001"))
      .mockResolvedValue("ok");
    const { sleep, random } = harness();

    await withRetry(fn, {
      sleep,
      random,
      onRetry,
      operation: "findings.saveMany",
      baseDelayMs: 50,
    });

    expect(onRetry).toHaveBeenCalledTimes(1);
    expect(onRetry).toHaveBeenCalledWith({
      attempt: 1,
      delayMs: 50,
      operation: "findings.saveMany",
    });
  });

  it("carries no query text or parameters into telemetry", async () => {
    const onRetry = vi.fn();
    const fn = vi
      .fn()
      .mockRejectedValueOnce(pgError("08006"))
      .mockResolvedValue("ok");
    const { sleep, random } = harness();

    await withRetry(fn, { sleep, random, onRetry, operation: "findings.query" });

    const [info] = onRetry.mock.calls[0];
    expect(Object.keys(info).sort()).toEqual(["attempt", "delayMs", "operation"]);
  });
});
