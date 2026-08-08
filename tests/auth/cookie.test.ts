import { afterEach, describe, expect, it, vi } from "vitest";

import {
  buildClearedSessionCookie,
  buildSessionCookie,
  readSessionCookie,
  SESSION_COOKIE_NAME,
} from "@/lib/auth/cookie";

// `Object.defineProperty(process.env, …)` is rejected by Node's env proxy
// unless the descriptor is writable and enumerable. `vi.stubEnv` is what the
// rest of the suite already uses, and it restores the original value for us.
afterEach(() => {
  vi.unstubAllEnvs();
});

function setNodeEnv(value: "production" | "development"): void {
  vi.stubEnv("NODE_ENV", value);
}

describe("session cookie", () => {
  const EXPIRES = "2026-08-10T23:00:00.000Z";

  it("is HttpOnly, Lax and path-scoped to the whole site", () => {
    const cookie = buildSessionCookie("tok", EXPIRES);
    expect(cookie).toContain(`${SESSION_COOKIE_NAME}=tok`);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Path=/");
  });

  it("is Secure in production and not in development", () => {
    setNodeEnv("production");
    expect(buildSessionCookie("tok", EXPIRES)).toContain("Secure");
    setNodeEnv("development");
    expect(buildSessionCookie("tok", EXPIRES)).not.toContain("Secure");
  });

  it("clears by expiring in the past with an empty value", () => {
    const cookie = buildClearedSessionCookie();
    expect(cookie).toContain(`${SESSION_COOKIE_NAME}=;`);
    expect(cookie).toContain("Max-Age=0");
  });

  it("reads its own cookie out of a header", () => {
    expect(readSessionCookie(`${SESSION_COOKIE_NAME}=abc123`)).toBe("abc123");
    expect(readSessionCookie(`other=1; ${SESSION_COOKIE_NAME}=abc123; more=2`)).toBe("abc123");
  });

  it("returns null when absent, empty or malformed", () => {
    expect(readSessionCookie(null)).toBeNull();
    expect(readSessionCookie("")).toBeNull();
    expect(readSessionCookie("other=1")).toBeNull();
    expect(readSessionCookie(`${SESSION_COOKIE_NAME}=`)).toBeNull();
  });

  it("is not fooled by a cookie whose name merely ends with ours", () => {
    expect(readSessionCookie(`not_${SESSION_COOKIE_NAME}=evil`)).toBeNull();
  });
});
