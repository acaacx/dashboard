import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { GET as findingsGet } from "@/app/api/security/findings/route";
import { GET as scansGet, POST as scansPost } from "@/app/api/security/scans/route";
import { GET as statisticsGet } from "@/app/api/security/statistics/route";
import { clearMemoryAuth, useMemoryAuth, withSession } from "../helpers/session";

/**
 * The first tests for the API route handlers.
 *
 * Two assertions per route, and both matter: an anonymous request is refused,
 * and an authenticated request still returns what it returned before the
 * wrapper existed. The second is the one that catches a wrapper that swallows
 * query parsing or changes a status code.
 *
 * Handlers are imported statically. A dynamic `import()` built from a template
 * literal cannot be resolved through the `@/` alias at build time and fails.
 */

const ROUTES = [
  { name: "findings", url: "http://localhost/api/security/findings", handler: findingsGet },
  { name: "statistics", url: "http://localhost/api/security/statistics", handler: statisticsGet },
  { name: "scans", url: "http://localhost/api/security/scans", handler: scansGet },
] as const;

describe("protected API routes", () => {
  beforeEach(() => {
    useMemoryAuth();
  });

  afterEach(() => {
    clearMemoryAuth();
  });

  for (const route of ROUTES) {
    describe(route.name, () => {
      it("refuses an anonymous request with 401", async () => {
        const response = await route.handler(new Request(route.url));

        expect(response.status).toBe(401);
        await expect(response.json()).resolves.toMatchObject({
          error: { code: "UNAUTHORIZED" },
        });
      });

      it("serves an authenticated request", async () => {
        const { cookie } = await withSession(`${route.name}@example.com`);
        const response = await route.handler(
          new Request(route.url, { headers: { cookie } }),
        );

        expect(response.status).toBe(200);
      });
    });
  }

  it("still validates query parameters behind the wall", async () => {
    const { cookie } = await withSession("query@example.com");

    const response = await findingsGet(
      new Request("http://localhost/api/security/findings?page=notanumber", {
        headers: { cookie },
      }),
    );

    expect(response.status).toBe(400);
  });

  it("leaves scan ingestion on its own bearer token", async () => {
    const response = await scansPost(
      new Request("http://localhost/api/security/scans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      }),
    );

    // Whatever POST answers, it must not be the session guard's 401 — CI holds
    // a bearer token, not a cookie.
    const body = await response.json().catch(() => ({}));
    expect(body?.error?.code).not.toBe("UNAUTHORIZED");
  });
});
