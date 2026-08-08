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
