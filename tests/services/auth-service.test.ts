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
