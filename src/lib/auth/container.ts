import "server-only";

import { randomBytes } from "node:crypto";

import {
  configuredDataSource,
  configuredStorage,
  type StorageDriver,
} from "@/lib/security/container";
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

  const container: AuthContainer = {
    users,
    sessions,
    authService: new AuthService(users, sessions),
    storage,
  };

  container.devAccount = await seedDevAccount(container);

  return container;
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
