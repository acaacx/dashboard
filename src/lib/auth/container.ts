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
