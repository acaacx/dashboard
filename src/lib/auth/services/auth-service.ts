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
