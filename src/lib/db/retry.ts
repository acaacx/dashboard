/**
 * Transient-failure retry for database operations.
 *
 * Databases fail in two very different ways and conflating them is how retry
 * logic causes outages instead of preventing them:
 *
 *  - transient: the connection dropped, the server was restarting, the pool was
 *    exhausted, a transaction lost a deadlock race. Retrying is correct.
 *  - permanent: bad SQL, a constraint violation, a missing table, a type error.
 *    Retrying burns time and hides the bug. These fail immediately.
 *
 * Retrying writes is only safe here because every write this codebase performs
 * is an idempotent upsert keyed on `fingerprint` or `id` — replaying one lands
 * exactly the same row. Retry is applied at the OPERATION level, never to a
 * single statement inside an open transaction: a broken transaction is already
 * aborted server-side, so the whole unit is replayed from BEGIN.
 */

/**
 * PostgreSQL SQLSTATE codes worth retrying.
 * @see https://www.postgresql.org/docs/current/errcodes-appendix.html
 */
const RETRYABLE_SQL_STATES = new Set([
  // Class 08 — connection exception
  "08000", // connection_exception
  "08001", // sqlclient_unable_to_establish_sqlconnection
  "08003", // connection_does_not_exist
  "08004", // sqlserver_rejected_establishment_of_sqlconnection
  "08006", // connection_failure
  "08007", // transaction_resolution_unknown
  "08P01", // protocol_violation
  // Class 40 — transaction rollback (lost a race; the retry usually wins)
  "40001", // serialization_failure
  "40P01", // deadlock_detected
  // Class 53 — insufficient resources
  "53300", // too_many_connections
  "53400", // configuration_limit_exceeded
  // Class 57 — operator intervention (failover, restart, planned shutdown)
  "57P01", // admin_shutdown
  "57P02", // crash_shutdown
  "57P03", // cannot_connect_now
  "57P04", // database_dropped
]);

/** Node socket-level failures that mean "try again", not "the query is wrong". */
const RETRYABLE_SYSCALL_CODES = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "EPIPE",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ENETDOWN",
  "EAI_AGAIN", // transient DNS failure
]);

/**
 * pg surfaces some pool/connection failures as plain Error messages with no
 * code at all, so those are matched on text. Kept narrow on purpose — a broad
 * pattern here would retry genuine bugs.
 */
const RETRYABLE_MESSAGES = [
  /connection terminated/i,
  /connection ended unexpectedly/i,
  /timeout exceeded when trying to connect/i,
  /server closed the connection unexpectedly/i,
  /terminating connection due to administrator command/i,
  /the database system is (starting up|shutting down|in recovery)/i,
];

interface DatabaseErrorLike {
  code?: unknown;
  message?: unknown;
}

export function isRetryableDatabaseError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;

  const { code, message } = error as DatabaseErrorLike;

  if (typeof code === "string") {
    if (RETRYABLE_SQL_STATES.has(code)) return true;
    if (RETRYABLE_SYSCALL_CODES.has(code)) return true;
    // A recognised code that is not in either list is a real error — a
    // constraint violation or a syntax error. Do not retry it.
    return false;
  }

  if (typeof message === "string") {
    return RETRYABLE_MESSAGES.some((pattern) => pattern.test(message));
  }

  return false;
}

export interface RetryOptions {
  /** Retries AFTER the first attempt. 3 means up to 4 attempts total. */
  maxRetries?: number;
  /** First backoff step in milliseconds; doubles each attempt. */
  baseDelayMs?: number;
  /** Ceiling for a single backoff step. */
  maxDelayMs?: number;
  /** Short label used in telemetry. Never include SQL or parameters. */
  operation?: string;
  /** Injectable for tests. */
  sleep?: (ms: number) => Promise<void>;
  /** Injectable for deterministic jitter in tests. */
  random?: () => number;
  /** Called before each retry — used for logging/metrics. */
  onRetry?: (info: {
    attempt: number;
    delayMs: number;
    operation?: string;
  }) => void;
}

function envInt(name: string, fallback: number): number {
  const raw = Number(process.env[name]);
  return Number.isFinite(raw) && raw >= 0 ? Math.trunc(raw) : fallback;
}

export function defaultRetryOptions(): Required<
  Pick<RetryOptions, "maxRetries" | "baseDelayMs" | "maxDelayMs">
> {
  return {
    maxRetries: envInt("DATABASE_MAX_RETRIES", 3),
    baseDelayMs: envInt("DATABASE_RETRY_BASE_DELAY_MS", 100),
    maxDelayMs: envInt("DATABASE_RETRY_MAX_DELAY_MS", 2000),
  };
}

const defaultSleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Exponential backoff with full jitter.
 *
 * Jitter matters more than the backoff curve: without it, every request that
 * failed during a failover retries at the same instant and knocks the database
 * over again the moment it comes back.
 */
export function backoffDelay(
  attempt: number,
  baseDelayMs: number,
  maxDelayMs: number,
  random: () => number = Math.random,
): number {
  const exponential = Math.min(baseDelayMs * 2 ** attempt, maxDelayMs);
  return Math.round(random() * exponential);
}

/**
 * Run `fn`, retrying transient database failures with jittered backoff.
 *
 * The original error is rethrown once retries are exhausted — callers see the
 * real failure, not a wrapper that hides the SQLSTATE.
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const defaults = defaultRetryOptions();
  const maxRetries = options.maxRetries ?? defaults.maxRetries;
  const baseDelayMs = options.baseDelayMs ?? defaults.baseDelayMs;
  const maxDelayMs = options.maxDelayMs ?? defaults.maxDelayMs;
  const sleep = options.sleep ?? defaultSleep;
  const random = options.random ?? Math.random;

  let attempt = 0;

  for (;;) {
    try {
      return await fn();
    } catch (error) {
      if (attempt >= maxRetries || !isRetryableDatabaseError(error)) {
        throw error;
      }

      const delayMs = backoffDelay(attempt, baseDelayMs, maxDelayMs, random);
      options.onRetry?.({
        attempt: attempt + 1,
        delayMs,
        operation: options.operation,
      });

      await sleep(delayMs);
      attempt += 1;
    }
  }
}
