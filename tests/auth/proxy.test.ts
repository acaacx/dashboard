import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";

import { SESSION_COOKIE_NAME } from "@/lib/auth/cookie";
import { proxy } from "@/proxy";

/**
 * Proxy is a UX redirect, not a security boundary — it checks only that a
 * cookie is present, never that it is valid. These tests pin that contract so
 * nobody later mistakes it for the wall.
 */

function request(path: string, token?: string): NextRequest {
  const nextRequest = new NextRequest(new URL(path, "http://localhost"));
  if (token) nextRequest.cookies.set(SESSION_COOKIE_NAME, token);
  return nextRequest;
}

describe("proxy", () => {
  it("redirects an anonymous dashboard navigation to login with a next path", () => {
    const response = proxy(request("/dashboard/security"));
    const location = new URL(response.headers.get("location")!);

    expect(location.pathname).toBe("/login");
    expect(location.searchParams.get("next")).toBe("/dashboard/security");
  });

  it("does not redirect when a cookie is present", () => {
    const response = proxy(request("/dashboard", "anything-at-all"));
    expect(response.headers.get("location")).toBeNull();
  });

  it("leaves the login page alone", () => {
    expect(proxy(request("/login")).headers.get("location")).toBeNull();
  });

  it("leaves the API alone, because 401 is the right answer there, not a redirect", () => {
    expect(proxy(request("/api/security/findings")).headers.get("location")).toBeNull();
  });
});
