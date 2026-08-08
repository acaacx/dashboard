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
