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
