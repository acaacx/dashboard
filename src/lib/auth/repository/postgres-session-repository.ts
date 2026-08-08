import type { Pool } from "pg";

import {
  LOGIN_WINDOW_MS,
  MAX_LOGIN_ATTEMPTS,
  type Session,
} from "@/domain/auth/session";
import { normalizeEmail } from "@/domain/auth/user";
import { getPool } from "@/lib/db/pool";
import { withRetry } from "@/lib/db/retry";
import type { CreateSessionInput, SessionRepository } from "./session-repository";

/**
 * PostgreSQL-backed session store and login throttle.
 *
 * Sessions are keyed by the SHA-256 of the cookie value, so this table is
 * useless to anyone who reads it.
 *
 * The throttle is a fixed window per email. The upsert resets the window in the
 * same statement that increments the count, so two simultaneous failed logins
 * cannot interleave into a lost increment.
 */

interface SessionRow {
  token_hash: string;
  user_id: string;
  expires_at: Date;
  created_at: Date;
}

interface AttemptRow {
  window_started_at: Date;
  count: number;
}

function toSession(row: SessionRow): Session {
  return {
    tokenHash: row.token_hash,
    userId: row.user_id,
    expiresAt: row.expires_at.toISOString(),
    createdAt: row.created_at.toISOString(),
  };
}

export class PostgresSessionRepository implements SessionRepository {
  constructor(private readonly pool: Pool = getPool()) {}

  async create(input: CreateSessionInput): Promise<Session> {
    const result = await withRetry(() =>
      this.pool.query<SessionRow>(
        `INSERT INTO sessions (token_hash, user_id, expires_at)
         VALUES ($1, $2, $3)
         RETURNING token_hash, user_id, expires_at, created_at`,
        [input.tokenHash, input.userId, input.expiresAt],
      ),
    );
    return toSession(result.rows[0]!);
  }

  async findValid(tokenHash: string, now: Date = new Date()): Promise<Session | null> {
    const result = await withRetry(() =>
      this.pool.query<SessionRow>(
        `SELECT token_hash, user_id, expires_at, created_at
           FROM sessions
          WHERE token_hash = $1 AND expires_at > $2`,
        [tokenHash, now.toISOString()],
      ),
    );
    return result.rows[0] ? toSession(result.rows[0]) : null;
  }

  async remove(tokenHash: string): Promise<void> {
    await withRetry(() =>
      this.pool.query("DELETE FROM sessions WHERE token_hash = $1", [tokenHash]),
    );
  }

  async removeExpired(now: Date = new Date()): Promise<number> {
    const result = await withRetry(() =>
      this.pool.query("DELETE FROM sessions WHERE expires_at <= $1", [now.toISOString()]),
    );
    return result.rowCount ?? 0;
  }

  async recordFailedAttempt(email: string, now: Date = new Date()): Promise<void> {
    const windowStart = new Date(now.getTime() - LOGIN_WINDOW_MS).toISOString();

    await withRetry(() =>
      this.pool.query(
        `INSERT INTO login_attempts (email, window_started_at, count)
         VALUES ($1, $2, 1)
         ON CONFLICT (email) DO UPDATE
           SET count = CASE
                         WHEN login_attempts.window_started_at <= $3
                         THEN 1
                         ELSE login_attempts.count + 1
                       END,
               window_started_at = CASE
                         WHEN login_attempts.window_started_at <= $3
                         THEN $2
                         ELSE login_attempts.window_started_at
                       END`,
        [normalizeEmail(email), now.toISOString(), windowStart],
      ),
    );
  }

  async throttledUntil(email: string, now: Date = new Date()): Promise<string | null> {
    const result = await withRetry(() =>
      this.pool.query<AttemptRow>(
        "SELECT window_started_at, count FROM login_attempts WHERE email = $1",
        [normalizeEmail(email)],
      ),
    );

    const row = result.rows[0];
    if (!row) return null;

    const endsAt = row.window_started_at.getTime() + LOGIN_WINDOW_MS;
    if (now.getTime() >= endsAt) return null;
    if (row.count < MAX_LOGIN_ATTEMPTS) return null;

    return new Date(endsAt).toISOString();
  }

  async clearAttempts(email: string): Promise<void> {
    await withRetry(() =>
      this.pool.query("DELETE FROM login_attempts WHERE email = $1", [
        normalizeEmail(email),
      ]),
    );
  }
}
