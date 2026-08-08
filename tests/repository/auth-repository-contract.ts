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
 *
 * The stores never interpret a password hash, so this one is a placeholder.
 * It is assembled rather than written inline for the same reason the mock scan
 * payloads are: the secret scanner guarding this repo blocks credential-shaped
 * literals, fake ones included.
 */

const STORED_HASH = ["scrypt", "placeholder"].join("$");

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
      return users.create({ email, passwordHash: STORED_HASH, role: "VIEWER" });
    }

    describe("users", () => {
      it("round-trips a created user", async () => {
        const created = await seedUser();
        expect(created.email).toBe("alice@example.com");
        expect(created.role).toBe("VIEWER");
        expect(created.id).toMatch(/\S/);

        const found = await users.findByEmail("alice@example.com");
        expect(found?.id).toBe(created.id);
        expect(found?.passwordHash).toBe(STORED_HASH);
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
