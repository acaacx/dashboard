# Dashboard Authentication — Plan 1: The Wall

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put every dashboard page and read API behind a real login, with local accounts and revocable server-side sessions.

**Architecture:** Local users hashed with `scrypt` from `node:crypto`. A session is a row keyed by the SHA-256 of an opaque 32-byte token carried in an `HttpOnly` cookie, so logout is real revocation and a database dump yields no live sessions. Both a user store and a session store sit behind interfaces with in-memory and PostgreSQL implementations verified by one shared contract suite, exactly as `SecurityFindingRepository` already is. Enforcement is structural: `protectedRoute()` injects the session into API handlers, and `requireUser()` runs in the dashboard layout and in each page.

**Tech Stack:** Next.js 16 (App Router), React 19, TypeScript strict, `pg`, `zod`, Vitest. **No new dependency is added by this plan.**

Spec: `docs/superpowers/specs/2026-08-08-dashboard-authentication-design.md`

## Global Constraints

- **No new runtime dependency.** Hashing is `node:crypto` `scrypt`. If you reach for `bcrypt`, `argon2`, `next-auth`, `jose`, or `iron-session`, stop — the spec rejected that.
- **Roles ship unenforced in this plan.** The `role` column, the `UserRole` type and the CLI `--role` flag all land here. Nothing reads the role to make a decision until Plan 2. Do not add `requireApprover` or touch `setFindingStatusAction`.
- **`statusChangedBy` is Plan 2.** Do not add it, do not add migration `004`, do not touch `reconcileFinding`.
- **Fail closed.** Any guard that cannot determine a session denies the request. Never allow-on-error.
- **Never log a password or a session token.** Not in an error message, not in a `console.log`, not in a thrown `Error`.
- **Migrations are forward-only.** Add `db/migrations/003_auth.sql`. Never edit `001_init.sql` or `002_finding_status_reason.sql`.
- Emails are stored and compared **lowercased and trimmed**.
- Session lifetime is an absolute **12 hours**, no sliding renewal.
- Throttle is **10 failed attempts per 15 minutes per email**.
- Minimum password length is **12**. No composition rules.
- Port 5432 on the development machine is an SSH tunnel. The test container is on **5433**.
- Verification gate for every task: `npm run lint && npm run typecheck && npm test`. Run with `TEST_DATABASE_URL` set so the PostgreSQL suites run rather than skip:

```bash
export TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test
```

## File Structure

**Created**

| File | Responsibility |
|---|---|
| `db/migrations/003_auth.sql` | `users`, `sessions`, `login_attempts` |
| `src/domain/auth/user.ts` | `User`, `SessionUser`, `UserRole` — pure types |
| `src/domain/auth/session.ts` | `Session`, TTL and throttle constants |
| `src/domain/auth/errors.ts` | `AuthDomainError` hierarchy |
| `src/lib/auth/password.ts` | scrypt hash / verify / dummy-verify |
| `src/lib/auth/cookie.ts` | cookie name, `Set-Cookie` building, header parsing |
| `src/lib/auth/safe-next.ts` | open-redirect guard for `?next=` |
| `src/lib/auth/repository/user-repository.ts` | interface + `CreateUserInput` |
| `src/lib/auth/repository/session-repository.ts` | interface |
| `src/lib/auth/repository/memory-user-repository.ts` | in-memory users |
| `src/lib/auth/repository/memory-session-repository.ts` | in-memory sessions + throttle |
| `src/lib/auth/repository/postgres-user-repository.ts` | PostgreSQL users |
| `src/lib/auth/repository/postgres-session-repository.ts` | PostgreSQL sessions + throttle |
| `src/lib/auth/services/auth-service.ts` | authenticate, resolve, sign out, provision |
| `src/lib/auth/container.ts` | auth composition root |
| `src/lib/auth/guards.ts` | `getSessionUser`, `requireUser`, `protectedRoute` |
| `src/app/login/page.tsx` | login screen (server) |
| `src/app/login/login-form.tsx` | form (client) |
| `src/app/login/actions.ts` | `signInAction`, `signOutAction` |
| `src/app/login/form-state.ts` | shared form-state type, no `"use server"` |
| `src/proxy.ts` | cookie-presence redirect, UX only |
| `scripts/user.mjs` | `create \| list \| role \| delete` |

**Modified**

| File | Change |
|---|---|
| `src/app/dashboard/layout.tsx` | `requireUser()`, sign-out control |
| `src/app/dashboard/page.tsx` and the 3 sibling pages | `requireUser()` |
| `src/app/api/security/findings/route.ts` and 2 siblings | wrap in `protectedRoute` |
| `src/app/api/security/findings/[id]/route.ts` | wrap in `protectedRoute` |
| `src/lib/auth/container.ts` | dev-account seeding (Task 11) |
| `package.json` | `user` script |
| `.env.example`, `README.md` | documentation |

Auth gets its own composition root rather than joining `src/lib/security/container.ts`, which seeds mock findings — authentication must not depend on seeding. It reuses the exported `configuredStorage()` from that module and the shared pool from `src/lib/db/pool.ts`.

---

### Task 1: Schema and domain types

**Files:**
- Create: `db/migrations/003_auth.sql`
- Create: `src/domain/auth/user.ts`
- Create: `src/domain/auth/session.ts`
- Create: `src/domain/auth/errors.ts`
- Test: `tests/auth/schema.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `User`, `SessionUser`, `UserRole`, `USER_ROLES`, `isUserRole`, `toSessionUser`, `Session`, `SESSION_TTL_MS`, `MAX_LOGIN_ATTEMPTS`, `LOGIN_WINDOW_MS`, `AuthDomainError`, `InvalidCredentialsError`, `TooManyAttemptsError`, `DuplicateUserError`, `UserNotFoundError`, `WeakPasswordError`, `isAuthDomainError`.

- [x] **Step 1: Write the failing test**

`tests/auth/schema.test.ts`:

```ts
import { describe, expect, it, afterAll, beforeAll } from "vitest";

import { createScopedTestPool, prepareSchema, TEST_DATABASE_URL } from "../helpers/postgres";

const SCHEMA = "test_auth_schema";

if (!TEST_DATABASE_URL) {
  describe.skip("auth schema", () => {
    it("skipped: TEST_DATABASE_URL is not set", () => {});
  });
} else {
  const pool = createScopedTestPool(SCHEMA);

  beforeAll(async () => {
    await prepareSchema(pool, SCHEMA);
  });

  afterAll(async () => {
    await pool.end();
  });

  describe("auth schema", () => {
    it("creates users, sessions and login_attempts", async () => {
      const { rows } = await pool.query<{ table_name: string }>(
        `SELECT table_name FROM information_schema.tables
         WHERE table_schema = $1 ORDER BY table_name`,
        [SCHEMA],
      );
      const names = rows.map((row) => row.table_name);
      expect(names).toContain("users");
      expect(names).toContain("sessions");
      expect(names).toContain("login_attempts");
    });

    it("rejects a duplicate email", async () => {
      await pool.query(
        `INSERT INTO users (id, email, password_hash, role) VALUES ($1,$2,$3,$4)`,
        ["usr_1", "dup@example.com", "hash", "VIEWER"],
      );
      await expect(
        pool.query(
          `INSERT INTO users (id, email, password_hash, role) VALUES ($1,$2,$3,$4)`,
          ["usr_2", "dup@example.com", "hash", "VIEWER"],
        ),
      ).rejects.toThrow();
    });

    it("deletes a user's sessions with the user", async () => {
      await pool.query(
        `INSERT INTO users (id, email, password_hash, role) VALUES ($1,$2,$3,$4)`,
        ["usr_3", "cascade@example.com", "hash", "APPROVER"],
      );
      await pool.query(
        `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1,$2,now())`,
        ["hash_3", "usr_3"],
      );

      await pool.query("DELETE FROM users WHERE id = $1", ["usr_3"]);

      const { rows } = await pool.query("SELECT 1 FROM sessions WHERE user_id = $1", [
        "usr_3",
      ]);
      expect(rows).toHaveLength(0);
    });
  });
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/auth/schema.test.ts`
Expected: FAIL — `relation "users" does not exist`.

- [x] **Step 3: Write the migration**

`db/migrations/003_auth.sql`:

```sql
-- User accounts, sessions and login throttling.
--
-- Until now the application had no user authentication: anyone who could reach
-- the dashboard could move a CRITICAL finding to FALSE_POSITIVE, and a risk
-- acceptance carried a justification but no signature.
--
-- Passwords are stored as self-describing scrypt strings
-- (scrypt$N$r$p$salt$hash) so cost parameters can be raised later without
-- invalidating existing rows. Nothing here ever stores a plaintext password.
--
-- `sessions.token_hash` is the SHA-256 of the token in the user's cookie, never
-- the token. A dump of this table yields no usable sessions.
--
-- `role` is written by provisioning but not yet read by any decision. Shipping
-- the column now avoids a later backfill, where defaulting everyone to APPROVER
-- would grant exactly what the role split exists to withhold and defaulting
-- everyone to VIEWER would lock out every existing account.

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('VIEWER', 'APPROVER')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Sweeping expired sessions is a range scan over this index.
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);

-- Listing "who has sessions open" and cascading deletes both walk this.
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id);

-- Fixed-window login throttle. Keyed on the submitted email whether or not an
-- account exists, so the refusal message reveals nothing about which is which.
CREATE TABLE IF NOT EXISTS login_attempts (
  email             TEXT PRIMARY KEY,
  window_started_at TIMESTAMPTZ NOT NULL,
  count             INTEGER NOT NULL
);
```

- [x] **Step 4: Write the domain types**

`src/domain/auth/user.ts`:

```ts
/**
 * User identity.
 *
 * Pure types: no `pg`, no `zod`, no `next`. A component test may import
 * `SessionUser` under jsdom without booting a server runtime, which is the same
 * reason `src/lib/security/status-change.ts` stays dependency-free.
 */

export const USER_ROLES = ["VIEWER", "APPROVER"] as const;

export type UserRole = (typeof USER_ROLES)[number];

export function isUserRole(value: unknown): value is UserRole {
  return typeof value === "string" && (USER_ROLES as readonly string[]).includes(value);
}

/** A stored account. Carries the password hash, so it must never leave the repository layer. */
export interface User {
  id: string;
  email: string;
  passwordHash: string;
  role: UserRole;
  createdAt: string;
}

/**
 * What a guard hands to a page, an action or a route handler.
 *
 * Deliberately has no `passwordHash` field. A hash cannot be serialized to a
 * client by accident if it is never in the object the client-facing code holds.
 */
export interface SessionUser {
  id: string;
  email: string;
  role: UserRole;
}

export function toSessionUser(user: User): SessionUser {
  return { id: user.id, email: user.email, role: user.role };
}

/** Stored and compared lowercased, so Alice@… and alice@… are one account. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}
```

`src/domain/auth/session.ts`:

```ts
/**
 * Session and throttle contracts.
 *
 * A session is a row, not a signed blob: logout deletes it, so revocation is
 * real. `tokenHash` is the SHA-256 of the value in the cookie — the token
 * itself is never stored.
 */

export interface Session {
  tokenHash: string;
  userId: string;
  expiresAt: string;
  createdAt: string;
}

/**
 * Absolute lifetime, with no sliding renewal. Predictable, and it bounds how
 * long a stolen cookie is worth anything.
 */
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

/** Fixed-window login throttle. */
export const MAX_LOGIN_ATTEMPTS = 10;
export const LOGIN_WINDOW_MS = 15 * 60 * 1000;
```

`src/domain/auth/errors.ts`:

```ts
/**
 * Domain errors for authentication.
 *
 * Mirrors `src/domain/security/errors.ts`. Rule: an error names the shape of a
 * problem and never the credential. No error here accepts a password or a
 * session token, so none can leak one into a log or an HTTP body.
 */

export abstract class AuthDomainError extends Error {
  abstract readonly code: string;
  readonly httpStatus: number = 400;

  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }

  toJSON(): { code: string; message: string } {
    return { code: this.code, message: this.message };
  }
}

/**
 * Wrong password, or no such account. Deliberately one error for both: a
 * distinct "no such user" is an account-enumeration oracle.
 */
export class InvalidCredentialsError extends AuthDomainError {
  readonly code = "INVALID_CREDENTIALS";
  readonly httpStatus = 401;

  constructor() {
    super("Email or password is incorrect.");
  }
}

export class TooManyAttemptsError extends AuthDomainError {
  readonly code = "TOO_MANY_ATTEMPTS";
  readonly httpStatus = 429;
  readonly retryAfterSeconds: number;

  constructor(retryAfterSeconds: number) {
    const minutes = Math.max(1, Math.ceil(retryAfterSeconds / 60));
    super(`Too many attempts. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`);
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export class DuplicateUserError extends AuthDomainError {
  readonly code = "DUPLICATE_USER";
  readonly httpStatus = 409;

  constructor(email: string) {
    super(`An account already exists for ${email}.`);
  }
}

export class UserNotFoundError extends AuthDomainError {
  readonly code = "USER_NOT_FOUND";
  readonly httpStatus = 404;

  constructor(email: string) {
    super(`No account exists for ${email}.`);
  }
}

/** Never quotes the password, not even its length beyond the minimum. */
export class WeakPasswordError extends AuthDomainError {
  readonly code = "WEAK_PASSWORD";

  constructor(minimum: number) {
    super(`A password must be at least ${minimum} characters.`);
  }
}

export function isAuthDomainError(error: unknown): error is AuthDomainError {
  return error instanceof AuthDomainError;
}
```

- [x] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/auth/schema.test.ts`
Expected: PASS, 3 tests.

- [x] **Step 6: Full gate**

Run: `npm run lint && npm run typecheck && npm test`
Expected: all pass. Test count rises by 3.

- [x] **Step 7: Commit**

```bash
git add db/migrations/003_auth.sql src/domain/auth tests/auth/schema.test.ts
git commit -m "feat: add auth schema and domain types"
```

---

### Task 2: Password hashing

**Files:**
- Create: `src/lib/auth/password.ts`
- Test: `tests/auth/password.test.ts`

**Interfaces:**
- Consumes: `WeakPasswordError` from `@/domain/auth/errors`.
- Produces: `MIN_PASSWORD_LENGTH: number`, `hashPassword(password: string): Promise<string>`, `verifyPassword(password: string, stored: string): Promise<boolean>`, `burnDummyVerify(password: string): Promise<void>`.

- [x] **Step 1: Write the failing test**

`tests/auth/password.test.ts`:

```ts
import { describe, expect, it } from "vitest";

import {
  burnDummyVerify,
  hashPassword,
  MIN_PASSWORD_LENGTH,
  verifyPassword,
} from "@/lib/auth/password";
import { WeakPasswordError } from "@/domain/auth/errors";

const GOOD = "correct horse battery staple";

describe("password hashing", () => {
  it("verifies a password against its own hash", async () => {
    const stored = await hashPassword(GOOD);
    await expect(verifyPassword(GOOD, stored)).resolves.toBe(true);
  });

  it("rejects the wrong password", async () => {
    const stored = await hashPassword(GOOD);
    await expect(verifyPassword("wrong horse battery staple", stored)).resolves.toBe(false);
  });

  it("produces a different hash each time, so salts are not reused", async () => {
    expect(await hashPassword(GOOD)).not.toBe(await hashPassword(GOOD));
  });

  it("is self-describing", async () => {
    const stored = await hashPassword(GOOD);
    expect(stored.split("$")).toHaveLength(6);
    expect(stored.startsWith("scrypt$")).toBe(true);
  });

  it("rejects a tampered hash rather than throwing", async () => {
    const stored = await hashPassword(GOOD);
    const parts = stored.split("$");
    parts[5] = Buffer.from("not the right key").toString("base64url");
    await expect(verifyPassword(GOOD, parts.join("$"))).resolves.toBe(false);
  });

  it("rejects an unrecognised algorithm rather than throwing", async () => {
    await expect(verifyPassword(GOOD, "bcrypt$10$salt$hash")).resolves.toBe(false);
  });

  it("rejects a malformed stored value rather than throwing", async () => {
    await expect(verifyPassword(GOOD, "")).resolves.toBe(false);
    await expect(verifyPassword(GOOD, "scrypt$notanumber$8$1$c2FsdA$aGFzaA")).resolves.toBe(false);
  });

  it("refuses a password under the minimum length", async () => {
    await expect(hashPassword("a".repeat(MIN_PASSWORD_LENGTH - 1))).rejects.toBeInstanceOf(
      WeakPasswordError,
    );
  });

  it("burns comparable work for an account that does not exist", async () => {
    await expect(burnDummyVerify("anything at all")).resolves.toBeUndefined();
  });
});
```

- [x] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/auth/password.test.ts`
Expected: FAIL — cannot resolve `@/lib/auth/password`.

- [x] **Step 3: Write the implementation**

`src/lib/auth/password.ts`:

```ts
import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

import { WeakPasswordError } from "@/domain/auth/errors";

/**
 * Password hashing with scrypt from node:crypto.
 *
 * No dependency is added for this. The stored value is self-describing —
 * `scrypt$N$r$p$salt$hash` — so the cost parameters can be raised later and old
 * rows still verify against the parameters they were written with.
 *
 * N is 16384 rather than a larger power of two on purpose: scrypt's memory use
 * is roughly N * r * 128 bytes, which at N=16384, r=8 is 16 MB. Node's default
 * `maxmem` is 32 MB, so N=32768 would throw at runtime unless every call also
 * passed a raised `maxmem`. Staying under the default keeps the failure mode
 * out of the codebase entirely.
 */

const scryptAsync = promisify(scrypt);

export const MIN_PASSWORD_LENGTH = 12;

const ALGORITHM = "scrypt";
const N = 16384;
const R = 8;
const P = 1;
const KEY_LENGTH = 64;
const SALT_LENGTH = 16;

async function derive(
  password: string,
  salt: Buffer,
  n: number,
  r: number,
  p: number,
): Promise<Buffer> {
  return (await scryptAsync(password, salt, KEY_LENGTH, { N: n, r, p })) as Buffer;
}

export async function hashPassword(password: string): Promise<string> {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new WeakPasswordError(MIN_PASSWORD_LENGTH);
  }

  const salt = randomBytes(SALT_LENGTH);
  const key = await derive(password, salt, N, R, P);

  return [
    ALGORITHM,
    N,
    R,
    P,
    salt.toString("base64url"),
    key.toString("base64url"),
  ].join("$");
}

/**
 * Verify a password against a stored value.
 *
 * Returns false for anything it cannot make sense of rather than throwing. A
 * corrupt or foreign hash is a failed login, not a 500 — and a thrown error
 * here would distinguish "malformed row" from "wrong password" to a caller who
 * should learn neither.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 6) return false;

  const [algorithm, rawN, rawR, rawP, rawSalt, rawKey] = parts;
  if (algorithm !== ALGORITHM) return false;

  const n = Number(rawN);
  const r = Number(rawR);
  const p = Number(rawP);
  if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p)) return false;
  if (n <= 1 || r < 1 || p < 1) return false;

  try {
    const salt = Buffer.from(rawSalt!, "base64url");
    const expected = Buffer.from(rawKey!, "base64url");
    if (salt.length === 0 || expected.length === 0) return false;

    const actual = (await scryptAsync(password, salt, expected.length, {
      N: n,
      r,
      p,
    })) as Buffer;

    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

/**
 * A hash of a value nobody knows, used to spend comparable time when no account
 * matches the submitted email.
 *
 * Without this, a missing account returns far faster than a wrong password, and
 * the difference is a reliable account-enumeration oracle.
 */
const DUMMY_HASH_PROMISE = hashPassword(randomBytes(32).toString("base64url"));

export async function burnDummyVerify(password: string): Promise<void> {
  await verifyPassword(password, await DUMMY_HASH_PROMISE);
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/auth/password.test.ts`
Expected: PASS, 9 tests.

- [x] **Step 5: Full gate and commit**

```bash
npm run lint && npm run typecheck && npm test
git add src/lib/auth/password.ts tests/auth/password.test.ts
git commit -m "feat: hash passwords with scrypt from node:crypto"
```

---

### Task 3: Repository interfaces, in-memory stores, contract suite

**Files:**
- Create: `src/lib/auth/repository/user-repository.ts`
- Create: `src/lib/auth/repository/session-repository.ts`
- Create: `src/lib/auth/repository/memory-user-repository.ts`
- Create: `src/lib/auth/repository/memory-session-repository.ts`
- Test: `tests/repository/auth-repository-contract.ts`
- Test: `tests/repository/memory-auth-repository.test.ts`

**Interfaces:**
- Consumes: `User`, `UserRole`, `normalizeEmail` from `@/domain/auth/user`; `Session`, `MAX_LOGIN_ATTEMPTS`, `LOGIN_WINDOW_MS` from `@/domain/auth/session`; `DuplicateUserError` from `@/domain/auth/errors`.
- Produces:
  - `CreateUserInput { email: string; passwordHash: string; role: UserRole }`
  - `UserRepository` — `findByEmail`, `findById`, `create`, `list`, `setRole`, `remove`, `count`
  - `CreateSessionInput { tokenHash: string; userId: string; expiresAt: string }`
  - `SessionRepository` — `create`, `findValid`, `remove`, `removeExpired`, `recordFailedAttempt`, `throttledUntil`, `clearAttempts`
  - `InMemoryUserRepository`, `InMemorySessionRepository`
  - `runAuthRepositoryContract(name, factory)` from the test contract module

- [x] **Step 1: Write the contract suite**

`tests/repository/auth-repository-contract.ts`:

```ts
import { beforeEach, describe, expect, it } from "vitest";

import { DuplicateUserError } from "@/domain/auth/errors";
import { LOGIN_WINDOW_MS, MAX_LOGIN_ATTEMPTS } from "@/domain/auth/session";
import type { SessionRepository } from "@/lib/auth/repository/session-repository";
import type { UserRepository } from "@/lib/auth/repository/user-repository";

/**
 * Behavioural contract for the auth stores.
 *
 * Run against every implementation. The in-memory and PostgreSQL stores must
 * answer identically, including the awkward cases: email case folding, expiry
 * boundaries, cascade on user deletion, and a throttle window that reopens.
 *
 * A behaviour asserted here is a behaviour the application may rely on.
 */

const NOW = new Date("2026-08-10T12:00:00.000Z");

export interface AuthStores {
  users: UserRepository;
  sessions: SessionRepository;
}

export function runAuthRepositoryContract(
  name: string,
  factory: { create: () => Promise<AuthStores> },
): void {
  describe(`auth repository contract: ${name}`, () => {
    let users: UserRepository;
    let sessions: SessionRepository;

    beforeEach(async () => {
      ({ users, sessions } = await factory.create());
    });

    async function seedUser(email = "alice@example.com") {
      return users.create({ email, passwordHash: "scrypt$stored", role: "VIEWER" });
    }

    describe("users", () => {
      it("round-trips a created user", async () => {
        const created = await seedUser();
        expect(created.email).toBe("alice@example.com");
        expect(created.role).toBe("VIEWER");
        expect(created.id).toMatch(/\S/);

        const found = await users.findByEmail("alice@example.com");
        expect(found?.id).toBe(created.id);
        expect(found?.passwordHash).toBe("scrypt$stored");
      });

      it("finds a user by id", async () => {
        const created = await seedUser();
        expect((await users.findById(created.id))?.email).toBe("alice@example.com");
      });

      it("returns null for an unknown email or id", async () => {
        expect(await users.findByEmail("nobody@example.com")).toBeNull();
        expect(await users.findById("usr_nope")).toBeNull();
      });

      it("folds email case on write and on read", async () => {
        await users.create({
          email: "MixedCase@Example.COM",
          passwordHash: "h",
          role: "VIEWER",
        });
        expect((await users.findByEmail("mixedcase@example.com"))?.email).toBe(
          "mixedcase@example.com",
        );
        expect((await users.findByEmail("MIXEDCASE@EXAMPLE.COM"))?.email).toBe(
          "mixedcase@example.com",
        );
      });

      it("refuses a duplicate email regardless of case", async () => {
        await seedUser();
        await expect(
          users.create({ email: "ALICE@example.com", passwordHash: "h", role: "VIEWER" }),
        ).rejects.toBeInstanceOf(DuplicateUserError);
      });

      it("counts users", async () => {
        expect(await users.count()).toBe(0);
        await seedUser();
        expect(await users.count()).toBe(1);
      });

      it("lists users in email order", async () => {
        await seedUser("carol@example.com");
        await seedUser("alice@example.com");
        await seedUser("bob@example.com");
        expect((await users.list()).map((user) => user.email)).toEqual([
          "alice@example.com",
          "bob@example.com",
          "carol@example.com",
        ]);
      });

      it("changes a role and reports an unknown email", async () => {
        await seedUser();
        expect((await users.setRole("alice@example.com", "APPROVER"))?.role).toBe("APPROVER");
        expect((await users.findByEmail("alice@example.com"))?.role).toBe("APPROVER");
        expect(await users.setRole("nobody@example.com", "APPROVER")).toBeNull();
      });

      it("removes a user and reports whether one was removed", async () => {
        await seedUser();
        expect(await users.remove("alice@example.com")).toBe(true);
        expect(await users.findByEmail("alice@example.com")).toBeNull();
        expect(await users.remove("alice@example.com")).toBe(false);
      });
    });

    describe("sessions", () => {
      async function seedSession(expiresAt: Date, userId: string) {
        return sessions.create({
          tokenHash: "hash_1",
          userId,
          expiresAt: expiresAt.toISOString(),
        });
      }

      it("round-trips a valid session", async () => {
        const user = await seedUser();
        const expiresAt = new Date(NOW.getTime() + 60_000);
        await seedSession(expiresAt, user.id);

        const found = await sessions.findValid("hash_1", NOW);
        expect(found?.userId).toBe(user.id);
      });

      it("does not return an expired session", async () => {
        const user = await seedUser();
        await seedSession(new Date(NOW.getTime() - 1), user.id);
        expect(await sessions.findValid("hash_1", NOW)).toBeNull();
      });

      it("treats the expiry instant itself as expired", async () => {
        const user = await seedUser();
        await seedSession(NOW, user.id);
        expect(await sessions.findValid("hash_1", NOW)).toBeNull();
      });

      it("returns null for an unknown token hash", async () => {
        expect(await sessions.findValid("hash_absent", NOW)).toBeNull();
      });

      it("removes a session, which is what makes logout real", async () => {
        const user = await seedUser();
        await seedSession(new Date(NOW.getTime() + 60_000), user.id);
        await sessions.remove("hash_1");
        expect(await sessions.findValid("hash_1", NOW)).toBeNull();
      });

      it("sweeps only expired sessions", async () => {
        const user = await seedUser();
        await sessions.create({
          tokenHash: "hash_live",
          userId: user.id,
          expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
        });
        await sessions.create({
          tokenHash: "hash_dead",
          userId: user.id,
          expiresAt: new Date(NOW.getTime() - 60_000).toISOString(),
        });

        expect(await sessions.removeExpired(NOW)).toBe(1);
        expect(await sessions.findValid("hash_live", NOW)).not.toBeNull();
      });

      it("deletes a user's sessions when the user is removed", async () => {
        const user = await seedUser();
        await seedSession(new Date(NOW.getTime() + 60_000), user.id);

        await users.remove("alice@example.com");

        expect(await sessions.findValid("hash_1", NOW)).toBeNull();
      });
    });

    describe("login throttle", () => {
      const EMAIL = "target@example.com";

      it("does not throttle below the limit", async () => {
        for (let attempt = 0; attempt < MAX_LOGIN_ATTEMPTS - 1; attempt += 1) {
          await sessions.recordFailedAttempt(EMAIL, NOW);
        }
        expect(await sessions.throttledUntil(EMAIL, NOW)).toBeNull();
      });

      it("throttles at the limit and reports when it lifts", async () => {
        for (let attempt = 0; attempt < MAX_LOGIN_ATTEMPTS; attempt += 1) {
          await sessions.recordFailedAttempt(EMAIL, NOW);
        }
        const until = await sessions.throttledUntil(EMAIL, NOW);
        expect(until).not.toBeNull();
        expect(new Date(until!).getTime()).toBe(NOW.getTime() + LOGIN_WINDOW_MS);
      });

      it("reopens after the window passes", async () => {
        for (let attempt = 0; attempt < MAX_LOGIN_ATTEMPTS; attempt += 1) {
          await sessions.recordFailedAttempt(EMAIL, NOW);
        }
        const later = new Date(NOW.getTime() + LOGIN_WINDOW_MS + 1);
        expect(await sessions.throttledUntil(EMAIL, later)).toBeNull();
      });

      it("throttles the email whether or not an account exists", async () => {
        for (let attempt = 0; attempt < MAX_LOGIN_ATTEMPTS; attempt += 1) {
          await sessions.recordFailedAttempt("ghost@example.com", NOW);
        }
        expect(await sessions.throttledUntil("ghost@example.com", NOW)).not.toBeNull();
      });

      it("folds email case, so casing does not buy extra attempts", async () => {
        for (let attempt = 0; attempt < MAX_LOGIN_ATTEMPTS; attempt += 1) {
          await sessions.recordFailedAttempt("Target@Example.com", NOW);
        }
        expect(await sessions.throttledUntil(EMAIL, NOW)).not.toBeNull();
      });

      it("clears attempts on a successful login", async () => {
        for (let attempt = 0; attempt < MAX_LOGIN_ATTEMPTS; attempt += 1) {
          await sessions.recordFailedAttempt(EMAIL, NOW);
        }
        await sessions.clearAttempts(EMAIL);
        expect(await sessions.throttledUntil(EMAIL, NOW)).toBeNull();
      });
    });
  });
}
```

`tests/repository/memory-auth-repository.test.ts`:

```ts
import { InMemorySessionRepository } from "@/lib/auth/repository/memory-session-repository";
import { InMemoryUserRepository } from "@/lib/auth/repository/memory-user-repository";
import { runAuthRepositoryContract } from "./auth-repository-contract";

runAuthRepositoryContract("in-memory", {
  create: async () => {
    const users = new InMemoryUserRepository();
    // The memory driver has no foreign keys, so the session store is told about
    // the user store to reproduce ON DELETE CASCADE. The contract asserts both
    // drivers behave the same; this is how the memory side keeps that promise.
    const sessions = new InMemorySessionRepository();
    users.onRemoved((userId) => sessions.removeForUser(userId));
    return { users, sessions };
  },
});
```

- [x] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/repository/memory-auth-repository.test.ts`
Expected: FAIL — cannot resolve `@/lib/auth/repository/memory-user-repository`.

- [x] **Step 3: Write the interfaces**

`src/lib/auth/repository/user-repository.ts`:

```ts
import type { User, UserRole } from "@/domain/auth/user";

export interface CreateUserInput {
  email: string;
  passwordHash: string;
  role: UserRole;
}

/**
 * User store.
 *
 * Two implementations, one behavioural contract
 * (`tests/repository/auth-repository-contract.ts`). Every method takes and
 * returns the domain type; no SQL row shape escapes an implementation.
 *
 * Emails are normalized by the implementation, so callers may pass whatever the
 * user typed.
 */
export interface UserRepository {
  findByEmail(email: string): Promise<User | null>;
  findById(id: string): Promise<User | null>;
  /** Throws `DuplicateUserError` when the email is taken. */
  create(input: CreateUserInput): Promise<User>;
  /** Email order, so CLI output is stable. */
  list(): Promise<User[]>;
  /** Null when no such account. */
  setRole(email: string, role: UserRole): Promise<User | null>;
  /** True when an account was removed. Its sessions go with it. */
  remove(email: string): Promise<boolean>;
  count(): Promise<number>;
}
```

`src/lib/auth/repository/session-repository.ts`:

```ts
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
```

- [x] **Step 4: Write the in-memory implementations**

`src/lib/auth/repository/memory-user-repository.ts`:

```ts
import { randomUUID } from "node:crypto";

import { DuplicateUserError } from "@/domain/auth/errors";
import { normalizeEmail, type User, type UserRole } from "@/domain/auth/user";
import type { CreateUserInput, UserRepository } from "./user-repository";

/**
 * In-memory user store — the zero-setup development default.
 *
 * Behaviourally identical to the PostgreSQL store, which is what the shared
 * contract suite exists to prove.
 *
 * Accounts do not survive a restart. That is a documented limitation, not an
 * oversight: authentication on the memory driver is a development convenience.
 */
export class InMemoryUserRepository implements UserRepository {
  private readonly byId = new Map<string, User>();
  private readonly removalListeners: Array<(userId: string) => void> = [];

  /**
   * Notified when a user is removed, so the session store can drop that user's
   * sessions. PostgreSQL gets this from ON DELETE CASCADE; here it is wired by
   * hand in the composition root.
   */
  onRemoved(listener: (userId: string) => void): void {
    this.removalListeners.push(listener);
  }

  async findByEmail(email: string): Promise<User | null> {
    const normalized = normalizeEmail(email);
    for (const user of this.byId.values()) {
      if (user.email === normalized) return { ...user };
    }
    return null;
  }

  async findById(id: string): Promise<User | null> {
    const user = this.byId.get(id);
    return user ? { ...user } : null;
  }

  async create(input: CreateUserInput): Promise<User> {
    const email = normalizeEmail(input.email);
    if (await this.findByEmail(email)) {
      throw new DuplicateUserError(email);
    }

    const user: User = {
      id: `usr_${randomUUID()}`,
      email,
      passwordHash: input.passwordHash,
      role: input.role,
      createdAt: new Date().toISOString(),
    };
    this.byId.set(user.id, user);
    return { ...user };
  }

  async list(): Promise<User[]> {
    return [...this.byId.values()]
      .map((user) => ({ ...user }))
      .sort((left, right) => left.email.localeCompare(right.email));
  }

  async setRole(email: string, role: UserRole): Promise<User | null> {
    const existing = await this.findByEmail(email);
    if (!existing) return null;

    const updated: User = { ...existing, role };
    this.byId.set(updated.id, updated);
    return { ...updated };
  }

  async remove(email: string): Promise<boolean> {
    const existing = await this.findByEmail(email);
    if (!existing) return false;

    this.byId.delete(existing.id);
    for (const listener of this.removalListeners) listener(existing.id);
    return true;
  }

  async count(): Promise<number> {
    return this.byId.size;
  }
}
```

`src/lib/auth/repository/memory-session-repository.ts`:

```ts
import {
  LOGIN_WINDOW_MS,
  MAX_LOGIN_ATTEMPTS,
  type Session,
} from "@/domain/auth/session";
import { normalizeEmail } from "@/domain/auth/user";
import type { CreateSessionInput, SessionRepository } from "./session-repository";

interface AttemptWindow {
  startedAt: number;
  count: number;
}

/**
 * In-memory session store and login throttle.
 *
 * Sessions vanish on restart, which logs everyone out — acceptable for the
 * development driver and documented as such. The throttle counter resets too,
 * which is the one place the memory driver is weaker than PostgreSQL rather
 * than merely more forgetful.
 */
export class InMemorySessionRepository implements SessionRepository {
  private readonly byTokenHash = new Map<string, Session>();
  private readonly attempts = new Map<string, AttemptWindow>();

  async create(input: CreateSessionInput): Promise<Session> {
    const session: Session = {
      tokenHash: input.tokenHash,
      userId: input.userId,
      expiresAt: input.expiresAt,
      createdAt: new Date().toISOString(),
    };
    this.byTokenHash.set(session.tokenHash, session);
    return { ...session };
  }

  async findValid(tokenHash: string, now: Date = new Date()): Promise<Session | null> {
    const session = this.byTokenHash.get(tokenHash);
    if (!session) return null;
    if (new Date(session.expiresAt).getTime() <= now.getTime()) return null;
    return { ...session };
  }

  async remove(tokenHash: string): Promise<void> {
    this.byTokenHash.delete(tokenHash);
  }

  async removeExpired(now: Date = new Date()): Promise<number> {
    let removed = 0;
    for (const [tokenHash, session] of this.byTokenHash) {
      if (new Date(session.expiresAt).getTime() <= now.getTime()) {
        this.byTokenHash.delete(tokenHash);
        removed += 1;
      }
    }
    return removed;
  }

  /** Called by the composition root when a user is deleted; mirrors ON DELETE CASCADE. */
  removeForUser(userId: string): void {
    for (const [tokenHash, session] of this.byTokenHash) {
      if (session.userId === userId) this.byTokenHash.delete(tokenHash);
    }
  }

  async recordFailedAttempt(email: string, now: Date = new Date()): Promise<void> {
    const key = normalizeEmail(email);
    const window = this.attempts.get(key);

    if (!window || now.getTime() - window.startedAt >= LOGIN_WINDOW_MS) {
      this.attempts.set(key, { startedAt: now.getTime(), count: 1 });
      return;
    }

    window.count += 1;
  }

  async throttledUntil(email: string, now: Date = new Date()): Promise<string | null> {
    const window = this.attempts.get(normalizeEmail(email));
    if (!window) return null;

    const endsAt = window.startedAt + LOGIN_WINDOW_MS;
    if (now.getTime() >= endsAt) return null;
    if (window.count < MAX_LOGIN_ATTEMPTS) return null;

    return new Date(endsAt).toISOString();
  }

  async clearAttempts(email: string): Promise<void> {
    this.attempts.delete(normalizeEmail(email));
  }
}
```

- [x] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/repository/memory-auth-repository.test.ts`
Expected: PASS, 22 tests — 9 user, 7 session, 6 throttle.

- [x] **Step 6: Full gate and commit**

```bash
npm run lint && npm run typecheck && npm test
git add src/lib/auth/repository tests/repository/auth-repository-contract.ts tests/repository/memory-auth-repository.test.ts
git commit -m "feat: add auth repositories with an in-memory driver"
```

---

### Task 4: PostgreSQL stores

**Files:**
- Create: `src/lib/auth/repository/postgres-user-repository.ts`
- Create: `src/lib/auth/repository/postgres-session-repository.ts`
- Test: `tests/repository/postgres-auth-repository.test.ts`

**Interfaces:**
- Consumes: `UserRepository`, `SessionRepository`, `CreateUserInput`, `CreateSessionInput` from Task 3; `query`/`getPool` from `@/lib/db/pool`; `withRetry` from `@/lib/db/retry`.
- Produces: `PostgresUserRepository`, `PostgresSessionRepository`. Both take an optional `Pool` as their only constructor argument and default to the shared pool, matching `PostgresSecurityFindingRepository`.

- [x] **Step 1: Write the failing test**

`tests/repository/postgres-auth-repository.test.ts`:

```ts
import { afterAll, beforeAll, describe, it } from "vitest";

import { PostgresSessionRepository } from "@/lib/auth/repository/postgres-session-repository";
import { PostgresUserRepository } from "@/lib/auth/repository/postgres-user-repository";
import { createScopedTestPool, prepareSchema, TEST_DATABASE_URL } from "../helpers/postgres";
import { runAuthRepositoryContract } from "./auth-repository-contract";

/**
 * The full auth contract against a real PostgreSQL database.
 *
 * Skipped unless TEST_DATABASE_URL is set. This file owns its schema and wipes
 * it freely, so never point TEST_DATABASE_URL at anything real.
 */

const SCHEMA = "test_auth_contract";

if (!TEST_DATABASE_URL) {
  describe.skip("auth repository contract: postgres", () => {
    it("skipped: TEST_DATABASE_URL is not set", () => {});
  });
} else {
  const pool = createScopedTestPool(SCHEMA);

  beforeAll(async () => {
    await prepareSchema(pool, SCHEMA);
  });

  afterAll(async () => {
    await pool.end();
  });

  runAuthRepositoryContract("postgres", {
    create: async () => {
      // Truncate rather than recreate: same isolation, far faster. CASCADE
      // because sessions reference users.
      await pool.query("TRUNCATE users, sessions, login_attempts CASCADE");
      return {
        users: new PostgresUserRepository(pool),
        sessions: new PostgresSessionRepository(pool),
      };
    },
  });
}
```

- [x] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/repository/postgres-auth-repository.test.ts`
Expected: FAIL — cannot resolve `@/lib/auth/repository/postgres-user-repository`.

- [x] **Step 3: Write the user store**

`src/lib/auth/repository/postgres-user-repository.ts`:

```ts
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
```

- [x] **Step 4: Write the session store**

`src/lib/auth/repository/postgres-session-repository.ts`:

```ts
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
```

- [x] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/repository/postgres-auth-repository.test.ts`
Expected: PASS, 22 tests — the same contract the memory driver passes.

If any assertion differs between the two drivers, **fix the implementation, not the contract.** The contract is the specification.

- [x] **Step 6: Full gate and commit**

```bash
npm run lint && npm run typecheck && npm test
git add src/lib/auth/repository tests/repository/postgres-auth-repository.test.ts
git commit -m "feat: add the PostgreSQL auth stores"
```

---

### Task 5: Auth service

**Files:**
- Create: `src/lib/auth/services/auth-service.ts`
- Test: `tests/services/auth-service.test.ts`

**Interfaces:**
- Consumes: both repositories, `hashPassword`/`verifyPassword`/`burnDummyVerify`, the domain errors, `SESSION_TTL_MS`.
- Produces: `AuthService` with
  - `authenticate(email: string, password: string, now?: Date): Promise<{ token: string; expiresAt: string; user: SessionUser }>`
  - `resolveToken(token: string, now?: Date): Promise<SessionUser | null>`
  - `signOut(token: string): Promise<void>`
  - `createUser(email: string, password: string, role: UserRole): Promise<User>`
  - `listUsers(): Promise<User[]>`, `setRole(email, role)`, `removeUser(email)`, `userCount()`
  - `hashToken(token: string): string` exported as a module function

- [x] **Step 1: Write the failing test**

`tests/services/auth-service.test.ts`:

```ts
import { beforeEach, describe, expect, it } from "vitest";

import {
  InvalidCredentialsError,
  TooManyAttemptsError,
} from "@/domain/auth/errors";
import { MAX_LOGIN_ATTEMPTS, SESSION_TTL_MS } from "@/domain/auth/session";
import { InMemorySessionRepository } from "@/lib/auth/repository/memory-session-repository";
import { InMemoryUserRepository } from "@/lib/auth/repository/memory-user-repository";
import { AuthService, hashToken } from "@/lib/auth/services/auth-service";

const NOW = new Date("2026-08-10T12:00:00.000Z");
const PASSWORD = "correct horse battery staple";

describe("AuthService", () => {
  let users: InMemoryUserRepository;
  let sessions: InMemorySessionRepository;
  let service: AuthService;

  beforeEach(async () => {
    users = new InMemoryUserRepository();
    sessions = new InMemorySessionRepository();
    users.onRemoved((userId) => sessions.removeForUser(userId));
    service = new AuthService(users, sessions);
    await service.createUser("alice@example.com", PASSWORD, "APPROVER");
  });

  it("issues a session for correct credentials", async () => {
    const result = await service.authenticate("alice@example.com", PASSWORD, NOW);

    expect(result.user.email).toBe("alice@example.com");
    expect(result.user.role).toBe("APPROVER");
    expect(new Date(result.expiresAt).getTime()).toBe(NOW.getTime() + SESSION_TTL_MS);
    expect(result.token).toMatch(/\S{20,}/);
  });

  it("accepts the email in any case", async () => {
    await expect(
      service.authenticate("ALICE@Example.com", PASSWORD, NOW),
    ).resolves.toMatchObject({ user: { email: "alice@example.com" } });
  });

  it("stores only the hash of the token", async () => {
    const { token } = await service.authenticate("alice@example.com", PASSWORD, NOW);

    expect(await sessions.findValid(token, NOW)).toBeNull();
    expect(await sessions.findValid(hashToken(token), NOW)).not.toBeNull();
  });

  it("rejects a wrong password", async () => {
    await expect(
      service.authenticate("alice@example.com", "wrong password here", NOW),
    ).rejects.toBeInstanceOf(InvalidCredentialsError);
  });

  it("rejects an unknown email with the identical error", async () => {
    const unknown = await service
      .authenticate("ghost@example.com", PASSWORD, NOW)
      .catch((error: unknown) => error);
    const wrong = await service
      .authenticate("alice@example.com", "wrong password here", NOW)
      .catch((error: unknown) => error);

    expect(unknown).toBeInstanceOf(InvalidCredentialsError);
    expect((unknown as Error).message).toBe((wrong as Error).message);
  });

  it("throttles after the limit and keeps refusing the correct password", async () => {
    for (let attempt = 0; attempt < MAX_LOGIN_ATTEMPTS; attempt += 1) {
      await service.authenticate("alice@example.com", "wrong password here", NOW).catch(() => {});
    }

    await expect(
      service.authenticate("alice@example.com", PASSWORD, NOW),
    ).rejects.toBeInstanceOf(TooManyAttemptsError);
  });

  it("clears the throttle counter on a successful login", async () => {
    for (let attempt = 0; attempt < MAX_LOGIN_ATTEMPTS - 1; attempt += 1) {
      await service.authenticate("alice@example.com", "wrong password here", NOW).catch(() => {});
    }
    await service.authenticate("alice@example.com", PASSWORD, NOW);

    for (let attempt = 0; attempt < MAX_LOGIN_ATTEMPTS - 1; attempt += 1) {
      await service.authenticate("alice@example.com", "wrong password here", NOW).catch(() => {});
    }
    await expect(
      service.authenticate("alice@example.com", PASSWORD, NOW),
    ).resolves.toBeDefined();
  });

  it("resolves a live token to the user", async () => {
    const { token } = await service.authenticate("alice@example.com", PASSWORD, NOW);
    const user = await service.resolveToken(token, NOW);

    expect(user?.email).toBe("alice@example.com");
    expect(user).not.toHaveProperty("passwordHash");
  });

  it("does not resolve an expired token", async () => {
    const { token } = await service.authenticate("alice@example.com", PASSWORD, NOW);
    const later = new Date(NOW.getTime() + SESSION_TTL_MS + 1);

    expect(await service.resolveToken(token, later)).toBeNull();
  });

  it("does not resolve a token whose user was deleted", async () => {
    const { token } = await service.authenticate("alice@example.com", PASSWORD, NOW);
    await service.removeUser("alice@example.com");

    expect(await service.resolveToken(token, NOW)).toBeNull();
  });

  it("does not resolve a garbage token", async () => {
    expect(await service.resolveToken("not-a-real-token", NOW)).toBeNull();
    expect(await service.resolveToken("", NOW)).toBeNull();
  });

  it("makes logout real", async () => {
    const { token } = await service.authenticate("alice@example.com", PASSWORD, NOW);
    await service.signOut(token);

    expect(await service.resolveToken(token, NOW)).toBeNull();
  });

  it("never stores the password itself", async () => {
    const stored = await users.findByEmail("alice@example.com");
    expect(stored?.passwordHash).not.toContain(PASSWORD);
    expect(stored?.passwordHash.startsWith("scrypt$")).toBe(true);
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/services/auth-service.test.ts`
Expected: FAIL — cannot resolve `@/lib/auth/services/auth-service`.

- [x] **Step 3: Write the implementation**

`src/lib/auth/services/auth-service.ts`:

```ts
import { createHash, randomBytes } from "node:crypto";

import { InvalidCredentialsError, TooManyAttemptsError } from "@/domain/auth/errors";
import { SESSION_TTL_MS } from "@/domain/auth/session";
import { toSessionUser, type SessionUser, type User, type UserRole } from "@/domain/auth/user";
import { burnDummyVerify, hashPassword, verifyPassword } from "@/lib/auth/password";
import type { SessionRepository } from "@/lib/auth/repository/session-repository";
import type { UserRepository } from "@/lib/auth/repository/user-repository";

/**
 * Authentication and account provisioning.
 *
 * All decisions live here so the Server Action, the route guard and the CLI
 * share one implementation — the same reason metric definitions live in
 * SecurityService rather than in a chart.
 */

const TOKEN_BYTES = 32;

/**
 * The cookie carries the token; the store keeps only this.
 *
 * SHA-256 with no salt is deliberate and correct here: the input is 32 bytes of
 * CSPRNG output, so there is no dictionary to precompute and nothing a salt
 * would add. It has to be an unsalted digest anyway, because lookup is by hash.
 */
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export class AuthService {
  constructor(
    private readonly users: UserRepository,
    private readonly sessions: SessionRepository,
  ) {}

  /**
   * Verify credentials and open a session.
   *
   * Throws InvalidCredentialsError for both a wrong password and an unknown
   * email, and spends comparable time on each, so neither the message nor the
   * latency tells an attacker which accounts exist.
   */
  async authenticate(
    email: string,
    password: string,
    now: Date = new Date(),
  ): Promise<{ token: string; expiresAt: string; user: SessionUser }> {
    const until = await this.sessions.throttledUntil(email, now);
    if (until) {
      const seconds = Math.ceil((new Date(until).getTime() - now.getTime()) / 1000);
      throw new TooManyAttemptsError(seconds);
    }

    const user = await this.users.findByEmail(email);

    if (!user) {
      await burnDummyVerify(password);
      await this.sessions.recordFailedAttempt(email, now);
      throw new InvalidCredentialsError();
    }

    if (!(await verifyPassword(password, user.passwordHash))) {
      await this.sessions.recordFailedAttempt(email, now);
      throw new InvalidCredentialsError();
    }

    await this.sessions.clearAttempts(email);

    const token = randomBytes(TOKEN_BYTES).toString("base64url");
    const expiresAt = new Date(now.getTime() + SESSION_TTL_MS).toISOString();

    await this.sessions.create({ tokenHash: hashToken(token), userId: user.id, expiresAt });

    return { token, expiresAt, user: toSessionUser(user) };
  }

  /**
   * Resolve a cookie value to the user it belongs to, or null.
   *
   * Null covers every failure — absent, expired, forged, or belonging to a
   * deleted account — because the caller has exactly one correct response to
   * all of them.
   */
  async resolveToken(token: string, now: Date = new Date()): Promise<SessionUser | null> {
    if (!token) return null;

    const session = await this.sessions.findValid(hashToken(token), now);
    if (!session) return null;

    const user = await this.users.findById(session.userId);
    if (!user) return null;

    return toSessionUser(user);
  }

  async signOut(token: string): Promise<void> {
    if (!token) return;
    await this.sessions.remove(hashToken(token));
  }

  async createUser(email: string, password: string, role: UserRole): Promise<User> {
    const passwordHash = await hashPassword(password);
    return this.users.create({ email, passwordHash, role });
  }

  async listUsers(): Promise<User[]> {
    return this.users.list();
  }

  async setRole(email: string, role: UserRole): Promise<User | null> {
    return this.users.setRole(email, role);
  }

  async removeUser(email: string): Promise<boolean> {
    return this.users.remove(email);
  }

  async userCount(): Promise<number> {
    return this.users.count();
  }
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/services/auth-service.test.ts`
Expected: PASS, 13 tests.

- [x] **Step 5: Full gate and commit**

```bash
npm run lint && npm run typecheck && npm test
git add src/lib/auth/services tests/services/auth-service.test.ts
git commit -m "feat: add the auth service"
```

---

### Task 6: Cookie, safe redirect, container

**Files:**
- Create: `src/lib/auth/cookie.ts`
- Create: `src/lib/auth/safe-next.ts`
- Create: `src/lib/auth/container.ts`
- Test: `tests/auth/cookie.test.ts`
- Test: `tests/auth/safe-next.test.ts`

**Interfaces:**
- Consumes: `SESSION_TTL_MS`; `configuredStorage` from `@/lib/security/container`; both repository pairs; `AuthService`.
- Produces:
  - `SESSION_COOKIE_NAME = "dashboard_session"`
  - `buildSessionCookie(token: string, expiresAt: string): string`
  - `buildClearedSessionCookie(): string`
  - `readSessionCookie(header: string | null): string | null`
  - `safeNextPath(value: string | null | undefined): string`
  - `getAuthContainer(): Promise<AuthContainer>`, `getAuthService(): Promise<AuthService>`, `resetAuthContainer(): void`

- [x] **Step 1: Write the failing tests**

`tests/auth/cookie.test.ts`:

```ts
import { afterEach, describe, expect, it } from "vitest";

import {
  buildClearedSessionCookie,
  buildSessionCookie,
  readSessionCookie,
  SESSION_COOKIE_NAME,
} from "@/lib/auth/cookie";

const ORIGINAL_ENV = process.env.NODE_ENV;

afterEach(() => {
  Object.defineProperty(process.env, "NODE_ENV", { value: ORIGINAL_ENV, configurable: true });
});

function setNodeEnv(value: string): void {
  Object.defineProperty(process.env, "NODE_ENV", { value, configurable: true });
}

describe("session cookie", () => {
  const EXPIRES = "2026-08-10T23:00:00.000Z";

  it("is HttpOnly, Lax and path-scoped to the whole site", () => {
    const cookie = buildSessionCookie("tok", EXPIRES);
    expect(cookie).toContain(`${SESSION_COOKIE_NAME}=tok`);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Path=/");
  });

  it("is Secure in production and not in development", () => {
    setNodeEnv("production");
    expect(buildSessionCookie("tok", EXPIRES)).toContain("Secure");
    setNodeEnv("development");
    expect(buildSessionCookie("tok", EXPIRES)).not.toContain("Secure");
  });

  it("clears by expiring in the past with an empty value", () => {
    const cookie = buildClearedSessionCookie();
    expect(cookie).toContain(`${SESSION_COOKIE_NAME}=;`);
    expect(cookie).toContain("Max-Age=0");
  });

  it("reads its own cookie out of a header", () => {
    expect(readSessionCookie(`${SESSION_COOKIE_NAME}=abc123`)).toBe("abc123");
    expect(readSessionCookie(`other=1; ${SESSION_COOKIE_NAME}=abc123; more=2`)).toBe("abc123");
  });

  it("returns null when absent, empty or malformed", () => {
    expect(readSessionCookie(null)).toBeNull();
    expect(readSessionCookie("")).toBeNull();
    expect(readSessionCookie("other=1")).toBeNull();
    expect(readSessionCookie(`${SESSION_COOKIE_NAME}=`)).toBeNull();
  });

  it("is not fooled by a cookie whose name merely ends with ours", () => {
    expect(readSessionCookie(`not_${SESSION_COOKIE_NAME}=evil`)).toBeNull();
  });
});
```

`tests/auth/safe-next.test.ts`:

```ts
import { describe, expect, it } from "vitest";

import { safeNextPath } from "@/lib/auth/safe-next";

describe("safeNextPath", () => {
  it("keeps an ordinary in-app path", () => {
    expect(safeNextPath("/dashboard/security")).toBe("/dashboard/security");
    expect(safeNextPath("/dashboard?severity=CRITICAL")).toBe("/dashboard?severity=CRITICAL");
  });

  it("falls back when absent or empty", () => {
    expect(safeNextPath(null)).toBe("/dashboard");
    expect(safeNextPath(undefined)).toBe("/dashboard");
    expect(safeNextPath("")).toBe("/dashboard");
  });

  // A login page that redirects anywhere is the most convincing phishing link
  // there is: it genuinely starts on your own domain.
  it("refuses a protocol-relative URL", () => {
    expect(safeNextPath("//evil.example/login")).toBe("/dashboard");
    expect(safeNextPath("/\\evil.example")).toBe("/dashboard");
  });

  it("refuses a scheme-qualified URL", () => {
    expect(safeNextPath("https://evil.example")).toBe("/dashboard");
    expect(safeNextPath("javascript:alert(1)")).toBe("/dashboard");
  });

  it("refuses a backslash variant", () => {
    expect(safeNextPath("\\\\evil.example")).toBe("/dashboard");
  });

  it("refuses anything not rooted at /", () => {
    expect(safeNextPath("dashboard")).toBe("/dashboard");
    expect(safeNextPath("../etc/passwd")).toBe("/dashboard");
  });
});
```

- [x] **Step 2: Run to verify they fail**

Run: `npx vitest run tests/auth/cookie.test.ts tests/auth/safe-next.test.ts`
Expected: FAIL — modules do not resolve.

- [x] **Step 3: Write the implementations**

`src/lib/auth/cookie.ts`:

```ts
/**
 * Session cookie construction and parsing.
 *
 * Kept free of `next/headers` on purpose: route handlers parse the raw Cookie
 * header off the Request so their tests can call a handler directly with a
 * plain Request, without booting Next's async storage.
 */

export const SESSION_COOKIE_NAME = "dashboard_session";

function attributes(maxAgeSeconds: number, expires: string): string[] {
  const parts = [
    "Path=/",
    "HttpOnly",
    // Lax rather than Strict: Strict drops the cookie on a cross-site top-level
    // navigation, so following a link to the dashboard from a chat client would
    // land on the login page while signed in. Lax plus the origin checks
    // Next.js applies to Server Actions is the CSRF story.
    "SameSite=Lax",
    `Max-Age=${maxAgeSeconds}`,
    `Expires=${expires}`,
  ];

  // Secure would make the cookie unusable over plain http://localhost.
  if (process.env.NODE_ENV === "production") parts.push("Secure");

  return parts;
}

export function buildSessionCookie(token: string, expiresAt: string): string {
  const maxAge = Math.max(
    0,
    Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000),
  );
  return [
    `${SESSION_COOKIE_NAME}=${token}`,
    ...attributes(maxAge, new Date(expiresAt).toUTCString()),
  ].join("; ");
}

export function buildClearedSessionCookie(): string {
  return [
    `${SESSION_COOKIE_NAME}=`,
    ...attributes(0, new Date(0).toUTCString()),
  ].join("; ");
}

export function readSessionCookie(header: string | null): string | null {
  if (!header) return null;

  for (const pair of header.split(";")) {
    const index = pair.indexOf("=");
    if (index === -1) continue;

    const name = pair.slice(0, index).trim();
    if (name !== SESSION_COOKIE_NAME) continue;

    const value = pair.slice(index + 1).trim();
    return value === "" ? null : value;
  }

  return null;
}
```

`src/lib/auth/safe-next.ts`:

```ts
/**
 * Validate a post-login redirect target.
 *
 * `?next=` is supplied by whoever crafted the URL. Without this check the login
 * page is an open redirect, which makes the most convincing phishing link there
 * is: the victim really does start on your domain.
 *
 * Only a path rooted at a single `/` is accepted. Everything else — a
 * scheme, a protocol-relative `//host`, a backslash variant that some clients
 * normalize to `/`, or a bare relative path — falls back to the dashboard.
 */

const FALLBACK = "/dashboard";

export function safeNextPath(value: string | null | undefined): string {
  if (!value) return FALLBACK;
  if (!value.startsWith("/")) return FALLBACK;
  // `//host` is protocol-relative; `/\host` is normalized to it by some clients.
  if (value.startsWith("//") || value.startsWith("/\\")) return FALLBACK;
  return value;
}
```

`src/lib/auth/container.ts`:

```ts
import "server-only";

import { configuredStorage, type StorageDriver } from "@/lib/security/container";
import { InMemorySessionRepository } from "./repository/memory-session-repository";
import { InMemoryUserRepository } from "./repository/memory-user-repository";
import { PostgresSessionRepository } from "./repository/postgres-session-repository";
import { PostgresUserRepository } from "./repository/postgres-user-repository";
import type { SessionRepository } from "./repository/session-repository";
import type { UserRepository } from "./repository/user-repository";
import { AuthService } from "./services/auth-service";

/**
 * Composition root for authentication.
 *
 * Separate from the security container, which seeds mock findings on first
 * build — authentication must not depend on seeding, and the login path must
 * not pay for it. The storage driver decision is shared, so this reuses
 * `configuredStorage()` rather than re-deriving it.
 *
 * Server-only: importing it from a client component is a build error.
 */

export interface AuthContainer {
  users: UserRepository;
  sessions: SessionRepository;
  authService: AuthService;
  storage: StorageDriver;
}

async function buildContainer(): Promise<AuthContainer> {
  const storage = configuredStorage();

  let users: UserRepository;
  let sessions: SessionRepository;

  if (storage === "postgres") {
    users = new PostgresUserRepository();
    sessions = new PostgresSessionRepository();
  } else {
    const memoryUsers = new InMemoryUserRepository();
    const memorySessions = new InMemorySessionRepository();
    // PostgreSQL gets this from ON DELETE CASCADE. The memory driver has no
    // foreign keys, so the cascade is wired here — the contract suite asserts
    // both drivers behave the same.
    memoryUsers.onRemoved((userId) => memorySessions.removeForUser(userId));
    users = memoryUsers;
    sessions = memorySessions;
  }

  return { users, sessions, authService: new AuthService(users, sessions), storage };
}

/** Cached on globalThis so the memory store survives dev-server hot reloads. */
const CONTAINER_KEY = Symbol.for("dashboard.auth.container");

type GlobalWithContainer = typeof globalThis & {
  [CONTAINER_KEY]?: Promise<AuthContainer>;
};

export function getAuthContainer(): Promise<AuthContainer> {
  const globalRef = globalThis as GlobalWithContainer;
  globalRef[CONTAINER_KEY] ??= buildContainer();
  return globalRef[CONTAINER_KEY];
}

/** Test seam: drop the cached container so the next call rebuilds it. */
export function resetAuthContainer(): void {
  const globalRef = globalThis as GlobalWithContainer;
  delete globalRef[CONTAINER_KEY];
}

export async function getAuthService(): Promise<AuthService> {
  return (await getAuthContainer()).authService;
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `npx vitest run tests/auth/cookie.test.ts tests/auth/safe-next.test.ts`
Expected: PASS, 12 tests.

- [x] **Step 5: Full gate and commit**

```bash
npm run lint && npm run typecheck && npm test
git add src/lib/auth/cookie.ts src/lib/auth/safe-next.ts src/lib/auth/container.ts tests/auth
git commit -m "feat: add session cookie handling and the auth container"
```

---

### Task 7: Guards

**Files:**
- Create: `src/lib/auth/guards.ts`
- Test: `tests/auth/guards.test.ts`

**Interfaces:**
- Consumes: `getAuthService`, `readSessionCookie`, `SessionUser`.
- Produces:
  - `getSessionUserFromRequest(request: Request): Promise<SessionUser | null>`
  - `protectedRoute<Context = undefined>(handler: (request: Request, context: { user: SessionUser; routeContext: Context }) => Promise<Response>): (request: Request, routeContext: Context) => Promise<Response>`
  - `getSessionUser(): Promise<SessionUser | null>` (uses `next/headers`)
  - `requireUser(): Promise<SessionUser>` (redirects)

**Note on the two entry points:** `protectedRoute` reads the raw `Cookie` header off the `Request`, so a route test can call the handler with a plain `Request` and no Next runtime. `getSessionUser`/`requireUser` use `next/headers` because a server component has no `Request` to read.

- [x] **Step 1: Write the failing test**

`tests/auth/guards.test.ts`:

```ts
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { SESSION_COOKIE_NAME } from "@/lib/auth/cookie";
import { getAuthService, resetAuthContainer } from "@/lib/auth/container";
import { getSessionUserFromRequest, protectedRoute } from "@/lib/auth/guards";

/**
 * Guards are exercised against the real in-memory container rather than a mock,
 * because the behaviour under test is "does an unauthenticated request reach
 * the handler" — a mocked session store would assert nothing about that.
 */

const PASSWORD = "correct horse battery staple";

function requestWith(token?: string): Request {
  return new Request("http://localhost/api/security/statistics", {
    headers: token ? { cookie: `${SESSION_COOKIE_NAME}=${token}` } : {},
  });
}

describe("route guards", () => {
  let token: string;

  beforeEach(async () => {
    process.env.SECURITY_STORAGE = "memory";
    resetAuthContainer();

    const service = await getAuthService();
    await service.createUser("alice@example.com", PASSWORD, "APPROVER");
    ({ token } = await service.authenticate("alice@example.com", PASSWORD));
  });

  afterEach(() => {
    resetAuthContainer();
    delete process.env.SECURITY_STORAGE;
  });

  describe("getSessionUserFromRequest", () => {
    it("resolves a valid cookie", async () => {
      expect((await getSessionUserFromRequest(requestWith(token)))?.email).toBe(
        "alice@example.com",
      );
    });

    it("returns null with no cookie, a forged cookie, or a signed-out token", async () => {
      expect(await getSessionUserFromRequest(requestWith())).toBeNull();
      expect(await getSessionUserFromRequest(requestWith("forged"))).toBeNull();

      await (await getAuthService()).signOut(token);
      expect(await getSessionUserFromRequest(requestWith(token))).toBeNull();
    });
  });

  describe("protectedRoute", () => {
    const handler = protectedRoute(async (_request, { user }) =>
      Response.json({ email: user.email }),
    );

    it("runs the handler for an authenticated request", async () => {
      const response = await handler(requestWith(token));
      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({ email: "alice@example.com" });
    });

    it("refuses an anonymous request with 401 and never runs the handler", async () => {
      let ran = false;
      const spy = protectedRoute(async () => {
        ran = true;
        return Response.json({});
      });

      const response = await spy(requestWith());

      expect(response.status).toBe(401);
      expect(ran).toBe(false);
    });

    it("leaks nothing in the refusal body", async () => {
      const response = await handler(requestWith("forged"));
      const body = await response.text();

      expect(body).not.toContain("alice@example.com");
      expect(body).not.toContain("forged");
      expect(JSON.parse(body)).toMatchObject({ error: { code: "UNAUTHORIZED" } });
    });

    it("denies rather than allows when the session store throws", async () => {
      const service = await getAuthService();
      const guarded = protectedRoute(async () => Response.json({}));

      // Simulate a store that cannot answer: an auth check that fails open
      // during an outage is worse than none, because it looks like one.
      const original = service.resolveToken.bind(service);
      service.resolveToken = async () => {
        throw new Error("database unreachable");
      };

      try {
        expect((await guarded(requestWith(token))).status).toBe(401);
      } finally {
        service.resolveToken = original;
      }
    });
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/auth/guards.test.ts`
Expected: FAIL — cannot resolve `@/lib/auth/guards`.

- [x] **Step 3: Write the implementation**

`src/lib/auth/guards.ts`:

```ts
import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import type { SessionUser } from "@/domain/auth/user";
import { errorResponse } from "@/lib/api/http";
import { getAuthService } from "./container";
import { readSessionCookie, SESSION_COOKIE_NAME } from "./cookie";

/**
 * Authentication at the boundaries.
 *
 * Next.js 16 renamed `middleware.ts` to `proxy.ts` and moved it to the Node
 * runtime, so a session could technically be validated there. The framework's
 * own documentation says not to rely on it: a matcher change or a refactor that
 * moves a Server Function silently removes Proxy coverage. So `src/proxy.ts`
 * only redirects for UX, and every boundary validates for itself here.
 *
 * There are two entry points because there are two shapes of caller. Route
 * handlers hold a Request and parse its Cookie header, which also means their
 * tests can call them with a plain Request and no Next runtime. Server
 * components hold no Request and read the cookie store instead.
 */

/** Never distinguishes absent, expired, forged, or belonging-to-a-deleted-user. */
export async function getSessionUserFromRequest(
  request: Request,
): Promise<SessionUser | null> {
  const token = readSessionCookie(request.headers.get("cookie"));
  if (!token) return null;

  try {
    return await (await getAuthService()).resolveToken(token);
  } catch {
    // Fail closed. An unreachable store means "not authenticated", never
    // "authenticated" — an auth check that fails open during an outage is
    // worse than no check, because it looks like one.
    return null;
  }
}

/**
 * Wrap a route handler so it cannot run without a session.
 *
 * The session is an argument rather than something the handler fetches, so
 * forgetting the wrapper is a type error at the call site rather than a route
 * that is silently public.
 *
 * Generic over the route context so a dynamic segment keeps its types: a
 * `[id]` route declares `protectedRoute<{ params: Promise<{ id: string }> }>`
 * and reads `routeContext.params` with no cast.
 */
export function protectedRoute<Context = undefined>(
  handler: (
    request: Request,
    context: { user: SessionUser; routeContext: Context },
  ) => Promise<Response>,
): (request: Request, routeContext?: Context) => Promise<Response> {
  // routeContext is optional so a static route can be called with the request
  // alone, in a test or by Next. Next always supplies it for dynamic segments.
  return async (request: Request, routeContext?: Context) => {
    const user = await getSessionUserFromRequest(request);

    if (!user) {
      return errorResponse("UNAUTHORIZED", "Authentication is required.", 401);
    }

    return handler(request, { user, routeContext: routeContext as Context });
  };
}

/** Server-component and Server-Action path. Null when not signed in. */
export async function getSessionUser(): Promise<SessionUser | null> {
  const store = await cookies();
  const token = store.get(SESSION_COOKIE_NAME)?.value;
  if (!token) return null;

  try {
    return await (await getAuthService()).resolveToken(token);
  } catch {
    return null;
  }
}

/**
 * Require a session in a server component.
 *
 * Redirects to the plain login page rather than building a `?next=`: a server
 * component has no reliable view of the current URL, and `src/proxy.ts` — which
 * does — adds the parameter for navigations it intercepts.
 *
 * `redirect()` throws, so this never returns null.
 */
export async function requireUser(): Promise<SessionUser> {
  const user = await getSessionUser();
  if (!user) redirect("/login");
  return user;
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/auth/guards.test.ts`
Expected: PASS, 6 tests.

If the `next/headers` import makes the file fail to load under Vitest, note that the test only exercises `getSessionUserFromRequest` and `protectedRoute` — neither touches `cookies()`. If the module-level import itself throws in the test environment, move `cookies` to a dynamic `await import("next/headers")` inside `getSessionUser` and re-run.

- [x] **Step 5: Full gate and commit**

```bash
npm run lint && npm run typecheck && npm test
git add src/lib/auth/guards.ts tests/auth/guards.test.ts
git commit -m "feat: add structural route and page guards"
```

---

### Task 8: Login page and actions

**Files:**
- Create: `src/app/login/form-state.ts`
- Create: `src/app/login/actions.ts`
- Create: `src/app/login/login-form.tsx`
- Create: `src/app/login/page.tsx`
- Test: `tests/actions/sign-in-action.test.ts`

**Interfaces:**
- Consumes: `getAuthService`, `buildSessionCookie`, `buildClearedSessionCookie`, `SESSION_COOKIE_NAME`, `safeNextPath`, `isAuthDomainError`.
- Produces: `type SignInState = { error?: string }`, `signInAction(previous: SignInState, formData: FormData): Promise<SignInState>`, `signOutAction(): Promise<void>`.

- [x] **Step 1: Write the failing test**

`tests/actions/sign-in-action.test.ts`:

```ts
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { MAX_LOGIN_ATTEMPTS } from "@/domain/auth/session";
import { getAuthService, resetAuthContainer } from "@/lib/auth/container";

/**
 * The action is tested through its real service and store, with only the
 * Next.js edges — the cookie jar and redirect — stubbed. Mocking the service
 * would assert that the action calls a mock, not that a wrong password is
 * refused.
 */

const cookieSet = vi.fn();
const redirected = vi.fn();

vi.mock("next/headers", () => ({
  cookies: async () => ({ set: cookieSet, get: () => undefined, delete: vi.fn() }),
}));

vi.mock("next/navigation", () => ({
  redirect: (url: string) => {
    redirected(url);
    throw new Error("NEXT_REDIRECT");
  },
}));

const PASSWORD = "correct horse battery staple";

function formData(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [key, value] of Object.entries(fields)) data.append(key, value);
  return data;
}

describe("signInAction", () => {
  beforeEach(async () => {
    process.env.SECURITY_STORAGE = "memory";
    resetAuthContainer();
    cookieSet.mockReset();
    redirected.mockReset();

    await (await getAuthService()).createUser("alice@example.com", PASSWORD, "APPROVER");
  });

  afterEach(() => {
    resetAuthContainer();
    delete process.env.SECURITY_STORAGE;
    vi.restoreAllMocks();
  });

  async function signIn(fields: Record<string, string>) {
    const { signInAction } = await import("@/app/login/actions");
    return signInAction({}, formData(fields)).catch((error: Error) => {
      if (error.message === "NEXT_REDIRECT") return { redirected: true } as const;
      throw error;
    });
  }

  it("sets a session cookie and redirects on success", async () => {
    await signIn({ email: "alice@example.com", password: PASSWORD });

    expect(cookieSet).toHaveBeenCalledOnce();
    expect(redirected).toHaveBeenCalledWith("/dashboard");
  });

  it("honours a safe next path", async () => {
    await signIn({ email: "alice@example.com", password: PASSWORD, next: "/dashboard/security" });
    expect(redirected).toHaveBeenCalledWith("/dashboard/security");
  });

  it("refuses to redirect off-site", async () => {
    await signIn({ email: "alice@example.com", password: PASSWORD, next: "//evil.example" });
    expect(redirected).toHaveBeenCalledWith("/dashboard");
  });

  it("returns an error and sets no cookie for a wrong password", async () => {
    const state = await signIn({ email: "alice@example.com", password: "wrong password!!" });

    expect(state).toMatchObject({ error: "Email or password is incorrect." });
    expect(cookieSet).not.toHaveBeenCalled();
    expect(redirected).not.toHaveBeenCalled();
  });

  it("gives an unknown email the identical message", async () => {
    const state = await signIn({ email: "ghost@example.com", password: PASSWORD });
    expect(state).toMatchObject({ error: "Email or password is incorrect." });
  });

  it("rejects a missing field without reaching the service", async () => {
    expect(await signIn({ email: "", password: "" })).toMatchObject({
      error: "Enter an email and a password.",
    });
  });

  it("surfaces the throttle", async () => {
    for (let attempt = 0; attempt < MAX_LOGIN_ATTEMPTS; attempt += 1) {
      await signIn({ email: "alice@example.com", password: "wrong password!!" });
    }

    const state = await signIn({ email: "alice@example.com", password: PASSWORD });
    expect(state).toMatchObject({ error: expect.stringContaining("Too many attempts") });
  });

  it("never echoes the submitted password", async () => {
    const state = await signIn({ email: "alice@example.com", password: "wrong password!!" });
    expect(JSON.stringify(state)).not.toContain("wrong password!!");
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/actions/sign-in-action.test.ts`
Expected: FAIL — cannot resolve `@/app/login/actions`.

- [x] **Step 3: Write the shared state type**

`src/app/login/form-state.ts`:

```ts
/**
 * Form state shared by the action and the client form.
 *
 * Its own module, free of `"use server"`, so the client component can import
 * the type without pulling a server runtime into the browser bundle — the same
 * split as `src/lib/security/status-change.ts`.
 */
export interface SignInState {
  error?: string;
}
```

- [x] **Step 4: Write the actions**

`src/app/login/actions.ts`:

```ts
"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { isAuthDomainError } from "@/domain/auth/errors";
import {
  buildClearedSessionCookie,
  buildSessionCookie,
  SESSION_COOKIE_NAME,
} from "@/lib/auth/cookie";
import { getAuthService } from "@/lib/auth/container";
import { safeNextPath } from "@/lib/auth/safe-next";
import type { SignInState } from "./form-state";

/**
 * Sign in.
 *
 * A Server Action rather than a REST route: no credential reaches client
 * JavaScript, and there is no public endpoint accepting passwords.
 *
 * Failures come back as state, never as a throw. Only domain errors — which are
 * safe by construction and never carry a credential — pass their message
 * through; anything else is flattened, because an unexpected error's message
 * can contain an internal hostname.
 */
export async function signInAction(
  _previous: SignInState,
  formData: FormData,
): Promise<SignInState> {
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const next = safeNextPath(String(formData.get("next") ?? ""));

  if (!email || !password) {
    return { error: "Enter an email and a password." };
  }

  let cookieValue: string;

  try {
    const service = await getAuthService();
    const { token, expiresAt } = await service.authenticate(email, password);
    cookieValue = buildSessionCookie(token, expiresAt);
  } catch (error) {
    if (isAuthDomainError(error)) return { error: error.message };
    return { error: "Sign-in is unavailable. Try again shortly." };
  }

  await setRawCookie(cookieValue);

  // Outside the try: redirect() signals by throwing, and catching it here would
  // turn a successful sign-in into "Sign-in is unavailable".
  redirect(next);
}

export async function signOutAction(): Promise<void> {
  const store = await cookies();
  const token = store.get(SESSION_COOKIE_NAME)?.value;

  if (token) {
    // Delete the row, not just the cookie. Clearing the cookie alone leaves a
    // copied token working until it expires.
    await (await getAuthService()).signOut(token);
  }

  await setRawCookie(buildClearedSessionCookie());
  redirect("/login");
}

/**
 * Apply a fully-formed Set-Cookie string through the cookie jar.
 *
 * The attributes are built in one place (`src/lib/auth/cookie.ts`) so the
 * action, a future route and the tests cannot drift on HttpOnly or SameSite.
 */
async function setRawCookie(setCookie: string): Promise<void> {
  const [pair, ...rest] = setCookie.split("; ");
  const separator = pair!.indexOf("=");
  const name = pair!.slice(0, separator);
  const value = pair!.slice(separator + 1);

  const attributes = new Map(
    rest.map((part) => {
      const index = part.indexOf("=");
      return index === -1
        ? ([part.toLowerCase(), "true"] as const)
        : ([part.slice(0, index).toLowerCase(), part.slice(index + 1)] as const);
    }),
  );

  const store = await cookies();
  store.set({
    name,
    value,
    path: "/",
    httpOnly: attributes.has("httponly"),
    secure: attributes.has("secure"),
    sameSite: "lax",
    maxAge: Number(attributes.get("max-age") ?? 0),
  });
}
```

- [x] **Step 5: Write the form and page**

`src/app/login/login-form.tsx`:

```tsx
"use client";

import { useActionState } from "react";

import { signInAction } from "./actions";
import type { SignInState } from "./form-state";

const INITIAL: SignInState = {};

export function LoginForm({ next }: { next: string }) {
  const [state, formAction, pending] = useActionState(signInAction, INITIAL);

  return (
    <form action={formAction} className="flex flex-col gap-4">
      <input type="hidden" name="next" value={next} />

      <label className="flex flex-col gap-1.5">
        <span className="text-ink-faint font-mono text-[10px] tracking-[0.18em] uppercase">
          Email
        </span>
        <input
          name="email"
          type="email"
          autoComplete="username"
          required
          className="border-line bg-surface text-ink focus:border-accent rounded border px-3 py-2 text-sm outline-none"
        />
      </label>

      <label className="flex flex-col gap-1.5">
        <span className="text-ink-faint font-mono text-[10px] tracking-[0.18em] uppercase">
          Password
        </span>
        <input
          name="password"
          type="password"
          autoComplete="current-password"
          required
          className="border-line bg-surface text-ink focus:border-accent rounded border px-3 py-2 text-sm outline-none"
        />
      </label>

      {state.error && (
        <p role="alert" className="text-sm text-[var(--severity-high)]">
          {state.error}
        </p>
      )}

      <button
        type="submit"
        disabled={pending}
        className="bg-accent mt-1 rounded px-3 py-2 text-sm font-medium text-black disabled:opacity-60"
      >
        {pending ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
```

`src/app/login/page.tsx`:

```tsx
import { redirect } from "next/navigation";

import { getAuthContainer } from "@/lib/auth/container";
import { getSessionUser } from "@/lib/auth/guards";
import { safeNextPath } from "@/lib/auth/safe-next";
import { LoginForm } from "./login-form";

/**
 * Login screen — the one page outside the wall.
 *
 * force-dynamic for the same reason the dashboard pages are: a prerendered
 * login page would serve build-time state forever, including the "no accounts
 * exist" notice.
 */
export const dynamic = "force-dynamic";

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  const params = await searchParams;
  const next = safeNextPath(
    typeof params.next === "string" ? params.next : undefined,
  );

  // Already signed in: no reason to show a login form.
  if (await getSessionUser()) redirect(next);

  const { users } = await getAuthContainer();
  const hasAccounts = (await users.count()) > 0;

  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-sm flex-col justify-center px-6">
      <h1 className="text-ink text-lg font-semibold tracking-tight">DevSecOps</h1>
      <p className="text-ink-faint mb-7 font-mono text-[10px] tracking-[0.18em] uppercase">
        Control Plane
      </p>

      {hasAccounts ? (
        <LoginForm next={next} />
      ) : (
        <div className="border-line bg-surface/60 rounded border p-4">
          <p className="text-ink text-sm">No accounts exist yet.</p>
          <p className="text-ink-faint mt-2 text-sm">
            Create one, then sign in:
          </p>
          <pre className="text-ink-faint mt-3 overflow-x-auto font-mono text-xs">
            npm run user -- create --email you@example.com --role approver
          </pre>
        </div>
      )}
    </main>
  );
}
```

- [x] **Step 6: Run test to verify it passes**

Run: `npx vitest run tests/actions/sign-in-action.test.ts`
Expected: PASS, 8 tests.

- [x] **Step 7: Full gate and commit**

```bash
npm run lint && npm run typecheck && npm test
git add src/app/login tests/actions/sign-in-action.test.ts
git commit -m "feat: add the login page and sign-in action"
```

---

### Task 9: Gate the API routes

**Files:**
- Modify: `src/app/api/security/findings/route.ts`
- Modify: `src/app/api/security/findings/[id]/route.ts`
- Modify: `src/app/api/security/statistics/route.ts`
- Modify: `src/app/api/security/scans/route.ts` (GET only — leave POST alone)
- Create: `tests/helpers/session.ts`
- Test: `tests/api/protected-routes.test.ts`

**Interfaces:**
- Consumes: `protectedRoute` from `@/lib/auth/guards`.
- Produces: `withSession(): Promise<{ cookie: string }>` from `tests/helpers/session.ts`.

**These four routes have no tests today.** Nothing under `tests/` imports a handler from `src/app/api/`; the component suites stub global `fetch`. So this task writes the first ones, and they are what proves the wrapper preserves each route's behavior rather than merely refusing anonymous callers.

- [x] **Step 1: Write the test helper**

`tests/helpers/session.ts`:

```ts
import { SESSION_COOKIE_NAME } from "@/lib/auth/cookie";
import { getAuthService, resetAuthContainer } from "@/lib/auth/container";

/**
 * Create a real account and session against the configured store and return a
 * Cookie header for it.
 *
 * A real session rather than a stubbed guard: the thing under test is whether
 * an anonymous request reaches a handler, and a stubbed guard would assert
 * nothing about that.
 */
export async function withSession(
  email = "tester@example.com",
  role: "VIEWER" | "APPROVER" = "APPROVER",
): Promise<{ cookie: string; email: string }> {
  const password = "correct horse battery staple";
  const service = await getAuthService();

  await service.createUser(email, password, role);
  const { token } = await service.authenticate(email, password);

  return { cookie: `${SESSION_COOKIE_NAME}=${token}`, email };
}

/** Force the memory driver and drop any cached container. Call in beforeEach. */
export function useMemoryAuth(): void {
  process.env.SECURITY_STORAGE = "memory";
  resetAuthContainer();
}

export function clearMemoryAuth(): void {
  resetAuthContainer();
  delete process.env.SECURITY_STORAGE;
}
```

- [x] **Step 2: Write the failing test**

`tests/api/protected-routes.test.ts`:

```ts
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { GET as findingsGet } from "@/app/api/security/findings/route";
import { GET as scansGet, POST as scansPost } from "@/app/api/security/scans/route";
import { GET as statisticsGet } from "@/app/api/security/statistics/route";
import { clearMemoryAuth, useMemoryAuth, withSession } from "../helpers/session";

/**
 * The first tests for the API route handlers.
 *
 * Two assertions per route, and both matter: an anonymous request is refused,
 * and an authenticated request still returns what it returned before the
 * wrapper existed. The second is the one that catches a wrapper that swallows
 * query parsing or changes a status code.
 *
 * Handlers are imported statically. A dynamic `import()` built from a template
 * literal cannot be resolved through the `@/` alias at build time and fails.
 */

const ROUTES = [
  { name: "findings", url: "http://localhost/api/security/findings", handler: findingsGet },
  { name: "statistics", url: "http://localhost/api/security/statistics", handler: statisticsGet },
  { name: "scans", url: "http://localhost/api/security/scans", handler: scansGet },
] as const;

describe("protected API routes", () => {
  beforeEach(() => {
    useMemoryAuth();
  });

  afterEach(() => {
    clearMemoryAuth();
  });

  for (const route of ROUTES) {
    describe(route.name, () => {
      it("refuses an anonymous request with 401", async () => {
        const response = await route.handler(new Request(route.url));

        expect(response.status).toBe(401);
        await expect(response.json()).resolves.toMatchObject({
          error: { code: "UNAUTHORIZED" },
        });
      });

      it("serves an authenticated request", async () => {
        const { cookie } = await withSession(`${route.name}@example.com`);
        const response = await route.handler(
          new Request(route.url, { headers: { cookie } }),
        );

        expect(response.status).toBe(200);
      });
    });
  }

  it("still validates query parameters behind the wall", async () => {
    const { cookie } = await withSession("query@example.com");

    const response = await findingsGet(
      new Request("http://localhost/api/security/findings?page=notanumber", {
        headers: { cookie },
      }),
    );

    expect(response.status).toBe(400);
  });

  it("leaves scan ingestion on its own bearer token", async () => {
    const response = await scansPost(
      new Request("http://localhost/api/security/scans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      }),
    );

    // Whatever POST answers, it must not be the session guard's 401 — CI holds
    // a bearer token, not a cookie.
    const body = await response.json().catch(() => ({}));
    expect(body?.error?.code).not.toBe("UNAUTHORIZED");
  });
});
```

- [x] **Step 3: Run to verify it fails**

Run: `npx vitest run tests/api/protected-routes.test.ts`
Expected: FAIL — anonymous requests currently return 200, not 401.

- [x] **Step 4: Wrap the handlers**

For `src/app/api/security/statistics/route.ts`, change the export and add the import. Everything inside the function body stays exactly as it is:

```ts
import { errorResponse, errorToResponse, jsonResponse } from "@/lib/api/http";
import { protectedRoute } from "@/lib/auth/guards";
import { getSecurityService } from "@/lib/security/container";
// … existing imports unchanged

/**
 * GET /api/security/statistics
 *
 * … existing doc comment unchanged …
 *
 * Requires a session. The findings list names real vulnerabilities in real
 * repositories, so an anonymous read API would be a bypass around the UI's
 * login wall rather than a convenience.
 */
export const GET = protectedRoute(async (request: Request): Promise<Response> => {
  try {
    // … existing body verbatim …
  } catch (error) {
    return errorToResponse(error);
  }
});
```

Apply the same transformation to:
- `src/app/api/security/findings/route.ts`
- `src/app/api/security/scans/route.ts` — **the `GET` export only.** Leave `POST` and its `requireIngestAuth` call untouched.
- `src/app/api/security/findings/[id]/route.ts` — this one receives route params. Declare the context type so no cast is needed:

```ts
export const GET = protectedRoute<{ params: Promise<{ id: string }> }>(
  async (request, { routeContext }): Promise<Response> => {
    const { id } = await routeContext.params;
    // … existing body, using `id` exactly as before …
  },
);
```

Open the file first and match the shape the existing handler already declares for its second argument — if it uses `{ params: Promise<{ findingId: string }> }`, use that. `protectedRoute` forwards Next's context object through untouched as `routeContext`.

- [x] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/api/protected-routes.test.ts`
Expected: PASS, 8 tests.

- [x] **Step 6: Full gate and commit**

```bash
npm run lint && npm run typecheck && npm test
git add src/app/api tests/api tests/helpers/session.ts
git commit -m "feat: require a session for the read APIs"
```

---

### Task 10: Gate the dashboard, add proxy and sign-out

**Files:**
- Modify: `src/app/dashboard/layout.tsx`
- Modify: `src/app/dashboard/page.tsx`
- Modify: `src/app/dashboard/security/page.tsx`
- Modify: `src/app/dashboard/applications/page.tsx`
- Modify: `src/app/dashboard/pipelines/page.tsx`
- Create: `src/proxy.ts`
- Test: `tests/auth/proxy.test.ts`

**Interfaces:**
- Consumes: `requireUser` from `@/lib/auth/guards`, `signOutAction` from `@/app/login/actions`.
- Produces: `proxy(request: NextRequest): NextResponse` and `config` from `src/proxy.ts`.

- [x] **Step 1: Write the failing test**

`tests/auth/proxy.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";

import { SESSION_COOKIE_NAME } from "@/lib/auth/cookie";
import { proxy } from "@/proxy";

/**
 * Proxy is a UX redirect, not a security boundary — it checks only that a
 * cookie is present, never that it is valid. These tests pin that contract so
 * nobody later mistakes it for the wall.
 */

function request(path: string, token?: string): NextRequest {
  const nextRequest = new NextRequest(new URL(path, "http://localhost"));
  if (token) nextRequest.cookies.set(SESSION_COOKIE_NAME, token);
  return nextRequest;
}

describe("proxy", () => {
  it("redirects an anonymous dashboard navigation to login with a next path", () => {
    const response = proxy(request("/dashboard/security"));
    const location = new URL(response.headers.get("location")!);

    expect(location.pathname).toBe("/login");
    expect(location.searchParams.get("next")).toBe("/dashboard/security");
  });

  it("does not redirect when a cookie is present", () => {
    const response = proxy(request("/dashboard", "anything-at-all"));
    expect(response.headers.get("location")).toBeNull();
  });

  it("leaves the login page alone", () => {
    expect(proxy(request("/login")).headers.get("location")).toBeNull();
  });

  it("leaves the API alone, because 401 is the right answer there, not a redirect", () => {
    expect(proxy(request("/api/security/findings")).headers.get("location")).toBeNull();
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/auth/proxy.test.ts`
Expected: FAIL — cannot resolve `@/proxy`.

- [x] **Step 3: Write the proxy**

`src/proxy.ts`:

```ts
import { NextResponse, type NextRequest } from "next/server";

import { SESSION_COOKIE_NAME } from "@/lib/auth/cookie";

/**
 * NOT A SECURITY BOUNDARY.
 *
 * This file checks that a session cookie is *present*, never that it is valid.
 * It exists so an anonymous navigation lands on the login page without first
 * flashing the dashboard shell.
 *
 * Every real check happens at the boundary itself — `requireUser()` in the
 * layout and in each page, `protectedRoute()` on each API route. That is not
 * belt-and-braces; the Next.js documentation for this file is explicit:
 *
 *   "A matcher change or a refactor that moves a Server Function to a different
 *   route can silently remove Proxy coverage. Always verify authentication and
 *   authorization inside each Server Function rather than relying on Proxy
 *   alone."
 *
 * Proxy also warns against depending on shared modules or globals, and this
 * application's container is cached on globalThis. So no store is touched here.
 *
 * `middleware.ts` was renamed to `proxy.ts` in Next.js 16. Do not add a
 * `runtime` export — setting it in a Proxy file throws.
 */
export function proxy(request: NextRequest): NextResponse {
  const hasCookie = request.cookies.has(SESSION_COOKIE_NAME);
  if (hasCookie) return NextResponse.next();

  const { pathname, search } = request.nextUrl;
  const login = new URL("/login", request.url);
  login.searchParams.set("next", `${pathname}${search}`);

  return NextResponse.redirect(login);
}

export const config = {
  // Dashboard navigations only. The API answers 401 rather than redirecting —
  // a script following a redirect to an HTML login page gets a confusing 200.
  matcher: ["/dashboard/:path*"],
};
```

- [x] **Step 4: Gate the layout and pages**

In `src/app/dashboard/layout.tsx`, add the import and the call, and render the signed-in identity with a sign-out control:

```tsx
import Link from "next/link";

import { SidebarNav } from "@/components/shell/sidebar-nav";
import { MockBadge } from "@/components/ui/badge";
import { signOutAction } from "@/app/login/actions";
import { requireUser } from "@/lib/auth/guards";
import { getSecurityContainer } from "@/lib/security/container";

export default async function DashboardLayout({ children }: LayoutProps<"/dashboard">) {
  // Redirects when absent. Not sufficient on its own — a layout does not re-run
  // on every client-side navigation — so each page calls requireUser() too.
  const user = await requireUser();
  const { usingMockData } = await getSecurityContainer();

  // … existing markup unchanged up to the sidebar footer …
```

Replace the sidebar footer block with:

```tsx
        <div className="mt-auto px-3">
          {usingMockData && <MockBadge />}

          <p className="text-ink-faint mt-3 truncate font-mono text-[10px]" title={user.email}>
            {user.email}
          </p>

          <form action={signOutAction}>
            <button
              type="submit"
              className="text-ink-faint hover:text-ink mt-1 font-mono text-[10px] tracking-[0.18em] uppercase"
            >
              Sign out
            </button>
          </form>

          <p className="text-ink-faint mt-3 font-mono text-[10px] leading-relaxed">
            Semgrep · Trivy
            <br />
            Checkov · Gitleaks
          </p>
        </div>
```

In each of the four page files, add the import and a call as the first statement of the component:

```ts
import { requireUser } from "@/lib/auth/guards";
```

```ts
  // Layouts do not re-run on every client-side navigation, so the layout check
  // is a redirect rather than a gate. This is the gate.
  await requireUser();
```

- [x] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/auth/proxy.test.ts`
Expected: PASS, 4 tests.

- [x] **Step 6: Full gate and commit**

```bash
npm run lint && npm run typecheck && npm test && npm run build
git add src/proxy.ts src/app/dashboard tests/auth/proxy.test.ts
git commit -m "feat: put the dashboard behind a session"
```

---

### Task 11: Dev account seeding

**Files:**
- Modify: `src/lib/auth/container.ts`
- Test: `tests/auth/dev-seed.test.ts`

**Interfaces:**
- Consumes: `AuthContainer`, `configuredDataSource` from `@/lib/security/container`.
- Produces: `AuthContainer.devAccount?: { email: string; password: string }`.

**Why this exists:** the CLI is a separate process, so against the memory driver it writes to a store the server cannot see. Without seeding, adding authentication makes `npm run dev` unusable — locked out with no way to create an account.

- [x] **Step 1: Write the failing test**

`tests/auth/dev-seed.test.ts`:

```ts
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { getAuthContainer, resetAuthContainer } from "@/lib/auth/container";

const ORIGINAL_NODE_ENV = process.env.NODE_ENV;

function setNodeEnv(value: string): void {
  Object.defineProperty(process.env, "NODE_ENV", { value, configurable: true });
}

describe("development account seeding", () => {
  beforeEach(() => {
    process.env.SECURITY_STORAGE = "memory";
    process.env.SECURITY_DATA_SOURCE = "mock";
    resetAuthContainer();
  });

  afterEach(() => {
    resetAuthContainer();
    delete process.env.SECURITY_STORAGE;
    delete process.env.SECURITY_DATA_SOURCE;
    setNodeEnv(ORIGINAL_NODE_ENV ?? "test");
  });

  it("seeds one approver on the memory driver in mock mode", async () => {
    setNodeEnv("development");
    const container = await getAuthContainer();

    expect(container.devAccount).toBeDefined();
    expect(await container.users.count()).toBe(1);

    const seeded = await container.users.findByEmail(container.devAccount!.email);
    expect(seeded?.role).toBe("APPROVER");
  });

  it("seeds an account that actually signs in", async () => {
    setNodeEnv("development");
    const container = await getAuthContainer();
    const { email, password } = container.devAccount!;

    await expect(container.authService.authenticate(email, password)).resolves.toBeDefined();
  });

  it("refuses to seed in production", async () => {
    setNodeEnv("production");
    const container = await getAuthContainer();

    expect(container.devAccount).toBeUndefined();
    expect(await container.users.count()).toBe(0);
  });

  it("does not seed in live mode", async () => {
    setNodeEnv("development");
    process.env.SECURITY_DATA_SOURCE = "live";
    resetAuthContainer();

    expect((await getAuthContainer()).devAccount).toBeUndefined();
  });

  it("does not seed onto the postgres driver", async () => {
    setNodeEnv("development");
    process.env.SECURITY_STORAGE = "postgres";
    resetAuthContainer();

    // Building the postgres container requires DATABASE_URL; the assertion is
    // that seeding is not attempted, so a throw about a missing URL is fine and
    // a seeded dev account is not.
    const container = await getAuthContainer().catch(() => null);
    expect(container?.devAccount).toBeUndefined();
  });
});
```

- [x] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/auth/dev-seed.test.ts`
Expected: FAIL — `devAccount` does not exist.

- [x] **Step 3: Add seeding to the container**

In `src/lib/auth/container.ts`, extend the interface and `buildContainer`:

```ts
import { configuredDataSource, configuredStorage, type StorageDriver } from "@/lib/security/container";
```

```ts
export interface AuthContainer {
  users: UserRepository;
  sessions: SessionRepository;
  authService: AuthService;
  storage: StorageDriver;
  /**
   * Present only when a development account was seeded. Surfaced so the server
   * log can print credentials that exist nowhere else.
   */
  devAccount?: { email: string; password: string };
}

const DEV_ACCOUNT_EMAIL = "dev@localhost";

/**
 * Seed one approver so `npm run dev` still works with zero setup.
 *
 * The provisioning CLI is a separate process, so against the memory driver it
 * writes to a store this server cannot see. Without this, adding authentication
 * would lock a developer out of their own dashboard with no way in.
 *
 * Refused outright in production. This is the same shape as the mock finding
 * data, which the UI already labels as fabricated — a real deployment uses
 * Postgres and the CLI.
 */
async function seedDevAccount(
  container: AuthContainer,
): Promise<{ email: string; password: string } | undefined> {
  if (process.env.NODE_ENV === "production") return undefined;
  if (container.storage !== "memory") return undefined;
  if (configuredDataSource() !== "mock") return undefined;
  if ((await container.users.count()) > 0) return undefined;

  // Random per boot rather than a constant: a fixed default password is the
  // kind of thing that survives into a deployment.
  const password = randomBytes(12).toString("base64url");
  await container.authService.createUser(DEV_ACCOUNT_EMAIL, password, "APPROVER");

  console.log(
    `\n  Development account seeded (memory storage, mock data):\n` +
      `    email:    ${DEV_ACCOUNT_EMAIL}\n` +
      `    password: ${password}\n` +
      `  Not created in production. Use \`npm run user -- create\` with a database.\n`,
  );

  return { email: DEV_ACCOUNT_EMAIL, password };
}
```

Add `import { randomBytes } from "node:crypto";` at the top, and at the end of `buildContainer`, replace the return with:

```ts
  const container: AuthContainer = {
    users,
    sessions,
    authService: new AuthService(users, sessions),
    storage,
  };

  container.devAccount = await seedDevAccount(container);

  return container;
```

- [x] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/auth/dev-seed.test.ts`
Expected: PASS, 5 tests.

- [x] **Step 5: Full gate and commit**

```bash
npm run lint && npm run typecheck && npm test
git add src/lib/auth/container.ts tests/auth/dev-seed.test.ts
git commit -m "feat: seed a development account so zero setup still works"
```

---

### Task 12: Provisioning CLI

**Files:**
- Create: `scripts/user.mjs`
- Modify: `package.json`
- Test: `tests/auth/user-cli.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks at runtime — the script talks to Postgres directly through `pg`, the same way `scripts/migrate.mjs` does, so it does not need Next's module resolution or `server-only`.
- Produces: `npm run user -- create|list|role|delete`.

**Design note:** the script duplicates the scrypt format rather than importing `src/lib/auth/password.ts`, because that module resolves through the `@/` alias and TypeScript. A test asserts the two agree — a password hashed by the CLI must verify through the application, or provisioning silently produces accounts nobody can use.

- [x] **Step 1: Write the failing test**

`tests/auth/user-cli.test.ts`:

```ts
import { execFile } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { verifyPassword } from "@/lib/auth/password";
import { createScopedTestPool, prepareSchema, TEST_DATABASE_URL } from "../helpers/postgres";

const run = promisify(execFile);

const SCRIPT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "scripts",
  "user.mjs",
);

const SCHEMA = "test_user_cli";
const PASSWORD = "correct horse battery staple";

async function cli(args: string[], env: Record<string, string> = {}) {
  return run("node", [SCRIPT, ...args], {
    env: {
      ...process.env,
      DATABASE_URL: `${TEST_DATABASE_URL}?options=-c%20search_path%3D${SCHEMA}`,
      SECURITY_STORAGE: "postgres",
      USER_CLI_PASSWORD: PASSWORD,
      ...env,
    },
  });
}

if (!TEST_DATABASE_URL) {
  describe.skip("user CLI", () => {
    it("skipped: TEST_DATABASE_URL is not set", () => {});
  });
} else {
  const pool = createScopedTestPool(SCHEMA);

  beforeAll(async () => {
    await prepareSchema(pool, SCHEMA);
  });

  afterAll(async () => {
    await pool.end();
  });

  describe("user CLI", () => {
    it("creates an account whose password verifies through the application", async () => {
      await cli(["create", "--email", "cli@example.com", "--role", "approver"]);

      const { rows } = await pool.query<{ password_hash: string; role: string }>(
        "SELECT password_hash, role FROM users WHERE email = $1",
        ["cli@example.com"],
      );

      expect(rows[0]?.role).toBe("APPROVER");
      // The CLI and the app must agree on the hash format, or provisioning
      // silently produces accounts nobody can sign in to.
      await expect(verifyPassword(PASSWORD, rows[0]!.password_hash)).resolves.toBe(true);
    });

    it("lists accounts", async () => {
      const { stdout } = await cli(["list"]);
      expect(stdout).toContain("cli@example.com");
      expect(stdout).not.toContain(PASSWORD);
      expect(stdout).not.toContain("scrypt$");
    });

    it("refuses a duplicate", async () => {
      await expect(cli(["create", "--email", "cli@example.com"])).rejects.toThrow();
    });

    it("refuses a short password", async () => {
      await expect(
        cli(["create", "--email", "short@example.com"], { USER_CLI_PASSWORD: "tooshort" }),
      ).rejects.toThrow();
    });

    it("changes a role", async () => {
      await cli(["role", "--email", "cli@example.com", "--role", "viewer"]);
      const { rows } = await pool.query<{ role: string }>(
        "SELECT role FROM users WHERE email = $1",
        ["cli@example.com"],
      );
      expect(rows[0]?.role).toBe("VIEWER");
    });

    it("deletes an account and its sessions", async () => {
      await pool.query(
        "INSERT INTO sessions (token_hash, user_id, expires_at) SELECT 'h', id, now() + interval '1 hour' FROM users WHERE email = $1",
        ["cli@example.com"],
      );

      await cli(["delete", "--email", "cli@example.com"]);

      const users = await pool.query("SELECT 1 FROM users WHERE email = $1", [
        "cli@example.com",
      ]);
      const sessions = await pool.query("SELECT 1 FROM sessions WHERE token_hash = 'h'");
      expect(users.rows).toHaveLength(0);
      expect(sessions.rows).toHaveLength(0);
    });

    it("refuses to run against the memory driver", async () => {
      await expect(
        run("node", [SCRIPT, "list"], {
          env: { ...process.env, DATABASE_URL: "", SECURITY_STORAGE: "memory" },
        }),
      ).rejects.toThrow();
    });
  });
}
```

- [x] **Step 2: Run to verify it fails**

Run: `npx vitest run tests/auth/user-cli.test.ts`
Expected: FAIL — `scripts/user.mjs` does not exist.

- [x] **Step 3: Write the script**

`scripts/user.mjs`:

```js
#!/usr/bin/env node
/**
 * Account provisioning.
 *
 * The admin surface for authentication. There is no self-signup: on a dashboard
 * listing exploitable vulnerabilities, anyone who could reach the login page
 * could otherwise grant themselves access.
 *
 *   npm run user -- create --email you@example.com --role approver
 *   npm run user -- list
 *   npm run user -- role --email you@example.com --role viewer
 *   npm run user -- delete --email them@example.com
 *
 * The password is prompted on stdin with echo disabled, never accepted as a
 * flag: argv is visible in `ps` and lands in shell history. USER_CLI_PASSWORD
 * exists for the test suite and is deliberately undocumented in --help.
 *
 * Talks to Postgres directly, like scripts/migrate.mjs, so it needs no
 * TypeScript build and no Next module resolution. The scrypt parameters below
 * MUST match src/lib/auth/password.ts — a test asserts a CLI-written hash
 * verifies through the application.
 */

import { createInterface } from "node:readline";
import { randomBytes, randomUUID, scrypt } from "node:crypto";
import { promisify } from "node:util";

import pg from "pg";

const scryptAsync = promisify(scrypt);

const MIN_PASSWORD_LENGTH = 12;
const N = 16384;
const R = 8;
const P = 1;
const KEY_LENGTH = 64;
const SALT_LENGTH = 16;

async function hashPassword(password) {
  if (password.length < MIN_PASSWORD_LENGTH) {
    fail(`A password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
  }
  const salt = randomBytes(SALT_LENGTH);
  const key = await scryptAsync(password, salt, KEY_LENGTH, { N, r: R, p: P });
  return ["scrypt", N, R, P, salt.toString("base64url"), key.toString("base64url")].join("$");
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index];
    if (!key?.startsWith("--")) fail(`Unexpected argument: ${key}`);
    options[key.slice(2)] = rest[index + 1];
  }
  return { command, options };
}

/** Read a password without echoing it, and confirm it. */
async function promptPassword() {
  if (process.env.USER_CLI_PASSWORD) return process.env.USER_CLI_PASSWORD;

  if (!process.stdin.isTTY) {
    fail("A password must be entered interactively. Run this in a terminal.");
  }

  const ask = (label) =>
    new Promise((resolve) => {
      const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
      process.stdout.write(label);

      // Suppress echo: the prompt is written, keystrokes are not.
      const onData = () => process.stdout.write("");
      process.stdin.on("data", onData);
      rl.question("", (answer) => {
        process.stdin.off("data", onData);
        rl.close();
        process.stdout.write("\n");
        resolve(answer);
      });
      rl.output.write = () => true;
    });

  const first = await ask("Password: ");
  const second = await ask("Confirm password: ");
  if (first !== second) fail("Passwords do not match.");
  return first;
}

function requireEmail(options) {
  const email = options.email?.trim().toLowerCase();
  if (!email || !email.includes("@")) fail("Pass --email you@example.com");
  return email;
}

function requireRole(options, fallback) {
  const role = (options.role ?? fallback)?.toUpperCase();
  if (role !== "VIEWER" && role !== "APPROVER") {
    fail("--role must be viewer or approver");
  }
  return role;
}

async function main() {
  const { command, options } = parseArgs(process.argv.slice(2));

  if (!command || command === "--help" || command === "help") {
    console.log(
      "Usage:\n" +
        "  npm run user -- create --email you@example.com [--role viewer|approver]\n" +
        "  npm run user -- list\n" +
        "  npm run user -- role --email you@example.com --role approver\n" +
        "  npm run user -- delete --email them@example.com\n",
    );
    process.exit(command ? 0 : 1);
  }

  const connectionString = process.env.DATABASE_URL?.trim();
  if (!connectionString) {
    fail(
      "DATABASE_URL is not set.\n" +
        "  Accounts live in the configured store, and this script is a separate\n" +
        "  process from the server — against the in-memory driver it would write\n" +
        "  to a store the server cannot see. Set DATABASE_URL and run\n" +
        "  `npm run db:migrate` first.\n" +
        "  With the memory driver, the dev server seeds an account and prints it.",
    );
  }

  const useSsl =
    !/sslmode=disable/i.test(connectionString) &&
    !/@(localhost|127\.0\.0\.1)[:/]/.test(connectionString);

  const client = new pg.Client({
    connectionString,
    ssl: useSsl ? { rejectUnauthorized: false } : undefined,
  });
  await client.connect();

  try {
    if (command === "create") {
      const email = requireEmail(options);
      const role = requireRole(options, "viewer");
      const passwordHash = await hashPassword(await promptPassword());

      try {
        await client.query(
          "INSERT INTO users (id, email, password_hash, role) VALUES ($1, $2, $3, $4)",
          [`usr_${randomUUID()}`, email, passwordHash, role],
        );
      } catch (error) {
        if (error.code === "23505") fail(`An account already exists for ${email}.`);
        throw error;
      }
      console.log(`Created ${email} (${role}).`);
      return;
    }

    if (command === "list") {
      const { rows } = await client.query(
        "SELECT email, role, created_at FROM users ORDER BY email ASC",
      );
      if (rows.length === 0) {
        console.log("No accounts exist.");
        return;
      }
      // Never prints password_hash. A hash in a terminal ends up in a scrollback
      // buffer, a screenshot, or a support ticket.
      for (const row of rows) {
        console.log(`${row.email}\t${row.role}\t${row.created_at.toISOString()}`);
      }
      return;
    }

    if (command === "role") {
      const email = requireEmail(options);
      const role = requireRole(options);
      const result = await client.query("UPDATE users SET role = $2 WHERE email = $1", [
        email,
        role,
      ]);
      if (result.rowCount === 0) fail(`No account exists for ${email}.`);
      console.log(`${email} is now ${role}.`);
      return;
    }

    if (command === "delete") {
      const email = requireEmail(options);
      // Sessions go with the user through ON DELETE CASCADE. Findings the user
      // decided on are untouched: attribution is a denormalized snapshot, so an
      // offboarded employee's risk acceptances stay intact and attributed.
      const result = await client.query("DELETE FROM users WHERE email = $1", [email]);
      if (result.rowCount === 0) fail(`No account exists for ${email}.`);
      console.log(`Deleted ${email}.`);
      return;
    }

    fail(`Unknown command: ${command}`);
  } finally {
    await client.end();
  }
}

main().catch((error) => {
  // Never print the error object: a pg error can carry parameter values, and
  // one of this script's parameters is a password hash.
  console.error(error.message);
  process.exit(1);
});
```

- [x] **Step 4: Register the script**

In `package.json`, add to `scripts`:

```json
    "user": "node scripts/user.mjs"
```

- [x] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/auth/user-cli.test.ts`
Expected: PASS, 7 tests.

- [x] **Step 6: Full gate and commit**

```bash
npm run lint && npm run typecheck && npm test
git add scripts/user.mjs package.json tests/auth/user-cli.test.ts
git commit -m "feat: add the account provisioning CLI"
```

---

### Task 13: Documentation and live verification

**Files:**
- Modify: `README.md`
- Modify: `.env.example`
- Modify: `CLAUDE.md`

**Interfaces:**
- Consumes: everything above.
- Produces: nothing code depends on.

- [x] **Step 1: Update `.env.example`**

Add after the "Scan ingestion" block:

```
# --- Authentication -------------------------------------------------------

# There is no secret to set. Sessions are opaque random tokens checked against
# stored hashes, so nothing needs signing, rotating, or protecting here.
#
# Accounts live in the configured store. With DATABASE_URL set:
#
#   npm run db:migrate
#   npm run user -- create --email you@example.com --role approver
#
# Without DATABASE_URL the in-memory driver seeds one development account and
# prints its credentials to the server log on boot. That never happens when
# NODE_ENV=production.
```

- [x] **Step 2: Update `README.md`**

Add an "Authentication" section covering: how to create the first account, what the dev seed does and when it refuses, the two roles and the fact that roles are recorded but not yet enforced, that logout is real revocation, and the 12-hour absolute session lifetime.

In "Known limitations", **remove** the entry beginning "Anyone who can reach the dashboard can change a finding's status" and **replace** it with:

```markdown
- Roles are recorded but not yet enforced: any signed-in account can change a
  finding's status, and no author is recorded on the decision. Both land with
  the second half of the authentication work.
- With the in-memory driver, accounts and sessions do not survive a restart, so
  the dashboard reseeds a development account on each boot. Authentication on
  the memory driver is a development convenience; a deployment means Postgres.
- The login throttle is a fixed window per email. On the memory driver its
  counter resets when the process restarts.
```

Update the test counts in the storage section to the numbers this plan actually produces — run `npm test` twice, once with `TEST_DATABASE_URL` and once without, and record both.

- [x] **Step 3: Update `CLAUDE.md`**

Under "Traps", add:

```markdown
- **`src/proxy.ts` is not a security boundary.** It checks that a session cookie
  exists, never that it is valid. Next's own docs warn that a matcher change
  silently drops Server Function coverage, so every boundary validates for
  itself — `requireUser()` in the layout *and* in each page, `protectedRoute()`
  on each API route. A page that only inherits the layout check is reachable by
  client-side navigation.
- **The scrypt parameters are duplicated in `scripts/user.mjs`.** The CLI runs
  outside TypeScript and cannot import `src/lib/auth/password.ts`. If you change
  N, r or p in one, change both — `tests/auth/user-cli.test.ts` asserts a
  CLI-written hash verifies through the application.
- **N is 16384 on purpose.** scrypt uses roughly N * r * 128 bytes; N=32768 with
  r=8 exceeds Node's 32 MB default `maxmem` and throws at runtime.
```

- [x] **Step 4: Live verification**

Start the dev server, then walk the whole path by hand. Do not skip this — none of the tests above exercise a real browser session.

```bash
npm run dev
```

Confirm, in order:

1. The server log prints a seeded development account.
2. Visiting `/dashboard` redirects to `/login`.
3. `curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/api/security/findings` returns `401`.
4. Signing in with the seeded credentials lands on `/dashboard` and the findings render.
5. The sidebar shows the signed-in email.
6. Visiting `/login?next=//evil.example` and signing in lands on `/dashboard`, not the external host.
7. Sign out returns to `/login`, and `/dashboard` redirects again.
8. A wrong password ten times produces the throttle message, and the correct password is still refused until the window passes.

- [x] **Step 5: Full gate and commit**

```bash
export TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test
npm run lint && npm run typecheck && npm test && npm run build
git add README.md .env.example CLAUDE.md
git commit -m "docs: document dashboard authentication"
```

---

## Done when

- `/dashboard` and all four `/api/security/*` read routes refuse an anonymous caller.
- `POST /api/security/scans` still works with only its bearer token.
- Logout deletes the session row, and the old cookie stops working immediately.
- The same contract suite passes against both the memory and PostgreSQL auth stores.
- `npm run dev` works with zero setup, and the dev seed refuses to run in production.
- `npm run lint && npm run typecheck && npm test && npm run build` passes with `TEST_DATABASE_URL` set.

Plan 2 then adds `requireApprover`, `statusChangedBy`, and the viewer/approver UI.
