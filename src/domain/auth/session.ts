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
