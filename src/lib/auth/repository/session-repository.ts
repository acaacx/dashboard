import type { Session } from "@/domain/auth/session";

export interface CreateSessionInput {
  tokenHash: string;
  userId: string;
  expiresAt: string;
}

/**
 * Session store, plus the login throttle.
 *
 * The throttle lives here rather than in a third repository because it shares
 * every property that matters with sessions: short-lived, write-heavy, and
 * meaningless to retain across a restart.
 *
 * `now` is a parameter rather than a call to `new Date()` inside the
 * implementation so expiry boundaries are testable without faking the clock.
 */
export interface SessionRepository {
  create(input: CreateSessionInput): Promise<Session>;
  /** Null when absent or expired. Expiry is exclusive: `expiresAt <= now` is expired. */
  findValid(tokenHash: string, now?: Date): Promise<Session | null>;
  remove(tokenHash: string): Promise<void>;
  /** Returns how many were swept. */
  removeExpired(now?: Date): Promise<number>;

  recordFailedAttempt(email: string, now?: Date): Promise<void>;
  /** ISO instant the throttle lifts, or null when not throttled. */
  throttledUntil(email: string, now?: Date): Promise<string | null>;
  clearAttempts(email: string): Promise<void>;
}
