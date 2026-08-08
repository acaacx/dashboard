import { randomUUID } from "node:crypto";
import type { Pool } from "pg";

import { DuplicateUserError } from "@/domain/auth/errors";
import { normalizeEmail, isUserRole, type User, type UserRole } from "@/domain/auth/user";
import { getPool } from "@/lib/db/pool";
import { withRetry } from "@/lib/db/retry";
import type { CreateUserInput, UserRepository } from "./user-repository";

/**
 * PostgreSQL-backed user store.
 *
 * Behaviourally identical to InMemoryUserRepository — both are verified against
 * the same contract suite, which is the point of the interface.
 *
 * A unique-violation on insert is translated to DuplicateUserError rather than
 * retried: it is a permanent error, and `isRetryableDatabaseError` must keep
 * treating constraint violations as permanent.
 */

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  role: string;
  created_at: Date;
}

const UNIQUE_VIOLATION = "23505";

function toUser(row: UserRow): User {
  return {
    id: row.id,
    email: row.email,
    passwordHash: row.password_hash,
    // A row whose role is not recognised is treated as the least privileged
    // value rather than trusted. The CHECK constraint makes this unreachable;
    // it stays because "unrecognised" must never mean "more access".
    role: isUserRole(row.role) ? row.role : "VIEWER",
    createdAt: row.created_at.toISOString(),
  };
}

const COLUMNS = "id, email, password_hash, role, created_at";

export class PostgresUserRepository implements UserRepository {
  constructor(private readonly pool: Pool = getPool()) {}

  private async query<T extends UserRow>(text: string, params: unknown[]): Promise<T[]> {
    const result = await this.pool.query<T>(text, params);
    return result.rows;
  }

  async findByEmail(email: string): Promise<User | null> {
    const rows = await withRetry(() =>
      this.query<UserRow>(`SELECT ${COLUMNS} FROM users WHERE email = $1`, [
        normalizeEmail(email),
      ]),
    );
    return rows[0] ? toUser(rows[0]) : null;
  }

  async findById(id: string): Promise<User | null> {
    const rows = await withRetry(() =>
      this.query<UserRow>(`SELECT ${COLUMNS} FROM users WHERE id = $1`, [id]),
    );
    return rows[0] ? toUser(rows[0]) : null;
  }

  async create(input: CreateUserInput): Promise<User> {
    const email = normalizeEmail(input.email);
    const id = `usr_${randomUUID()}`;

    try {
      const rows = await withRetry(() =>
        this.query<UserRow>(
          `INSERT INTO users (id, email, password_hash, role)
           VALUES ($1, $2, $3, $4)
           RETURNING ${COLUMNS}`,
          [id, email, input.passwordHash, input.role],
        ),
      );
      return toUser(rows[0]!);
    } catch (error) {
      if ((error as { code?: string }).code === UNIQUE_VIOLATION) {
        throw new DuplicateUserError(email);
      }
      throw error;
    }
  }

  async list(): Promise<User[]> {
    const rows = await withRetry(() =>
      this.query<UserRow>(`SELECT ${COLUMNS} FROM users ORDER BY email ASC`, []),
    );
    return rows.map(toUser);
  }

  async setRole(email: string, role: UserRole): Promise<User | null> {
    const rows = await withRetry(() =>
      this.query<UserRow>(
        `UPDATE users SET role = $2 WHERE email = $1 RETURNING ${COLUMNS}`,
        [normalizeEmail(email), role],
      ),
    );
    return rows[0] ? toUser(rows[0]) : null;
  }

  async remove(email: string): Promise<boolean> {
    const result = await withRetry(() =>
      this.pool.query("DELETE FROM users WHERE email = $1", [normalizeEmail(email)]),
    );
    return (result.rowCount ?? 0) > 0;
  }

  async count(): Promise<number> {
    const result = await withRetry(() =>
      this.pool.query<{ count: string }>("SELECT count(*)::text AS count FROM users", []),
    );
    return Number(result.rows[0]?.count ?? 0);
  }
}
