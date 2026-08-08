import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { SESSION_COOKIE_NAME } from "@/lib/auth/cookie";
import { getAuthService, resetAuthContainer } from "@/lib/auth/container";
import { getSessionUserFromRequest, protectedRoute } from "@/lib/auth/guards";

/**
 * Guards are exercised against the real in-memory container rather than a mock,
 * because the behaviour under test is "does an unauthenticated request reach
 * the handler" — a mocked session store would assert nothing about that.
 */

const PASSWORD = "correct horse battery staple";

function requestWith(token?: string): Request {
  return new Request("http://localhost/api/security/statistics", {
    headers: token ? { cookie: `${SESSION_COOKIE_NAME}=${token}` } : {},
  });
}

describe("route guards", () => {
  let token: string;

  beforeEach(async () => {
    process.env.SECURITY_STORAGE = "memory";
    resetAuthContainer();

    const service = await getAuthService();
    await service.createUser("alice@example.com", PASSWORD, "APPROVER");
    ({ token } = await service.authenticate("alice@example.com", PASSWORD));
  });

  afterEach(() => {
    resetAuthContainer();
    delete process.env.SECURITY_STORAGE;
  });

  describe("getSessionUserFromRequest", () => {
    it("resolves a valid cookie", async () => {
      expect((await getSessionUserFromRequest(requestWith(token)))?.email).toBe(
        "alice@example.com",
      );
    });

    it("returns null with no cookie, a forged cookie, or a signed-out token", async () => {
      expect(await getSessionUserFromRequest(requestWith())).toBeNull();
      expect(await getSessionUserFromRequest(requestWith("forged"))).toBeNull();

      await (await getAuthService()).signOut(token);
      expect(await getSessionUserFromRequest(requestWith(token))).toBeNull();
    });
  });

  describe("protectedRoute", () => {
    const handler = protectedRoute(async (_request, { user }) =>
      Response.json({ email: user.email }),
    );

    it("runs the handler for an authenticated request", async () => {
      const response = await handler(requestWith(token));
      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({ email: "alice@example.com" });
    });

    it("refuses an anonymous request with 401 and never runs the handler", async () => {
      let ran = false;
      const spy = protectedRoute(async () => {
        ran = true;
        return Response.json({});
      });

      const response = await spy(requestWith());

      expect(response.status).toBe(401);
      expect(ran).toBe(false);
    });

    it("leaks nothing in the refusal body", async () => {
      const response = await handler(requestWith("forged"));
      const body = await response.text();

      expect(body).not.toContain("alice@example.com");
      expect(body).not.toContain("forged");
      expect(JSON.parse(body)).toMatchObject({ error: { code: "UNAUTHORIZED" } });
    });

    it("denies rather than allows when the session store throws", async () => {
      const service = await getAuthService();
      const guarded = protectedRoute(async () => Response.json({}));

      // Simulate a store that cannot answer: an auth check that fails open
      // during an outage is worse than none, because it looks like one.
      const original = service.resolveToken.bind(service);
      service.resolveToken = async () => {
        throw new Error("database unreachable");
      };

      try {
        expect((await guarded(requestWith(token))).status).toBe(401);
      } finally {
        service.resolveToken = original;
      }
    });
  });
});
