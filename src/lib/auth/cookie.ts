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
