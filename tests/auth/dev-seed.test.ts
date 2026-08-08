import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getAuthContainer, resetAuthContainer } from "@/lib/auth/container";

// `Object.defineProperty(process.env, …)` is rejected by Node's env proxy, so
// NODE_ENV is stubbed the way the rest of the suite does it.
function setNodeEnv(value: "development" | "production"): void {
  vi.stubEnv("NODE_ENV", value);
}

describe("development account seeding", () => {
  beforeEach(() => {
    process.env.SECURITY_STORAGE = "memory";
    process.env.SECURITY_DATA_SOURCE = "mock";
    resetAuthContainer();
  });

  afterEach(() => {
    resetAuthContainer();
    delete process.env.SECURITY_STORAGE;
    delete process.env.SECURITY_DATA_SOURCE;
    vi.unstubAllEnvs();
  });

  it("seeds one approver on the memory driver in mock mode", async () => {
    setNodeEnv("development");
    const container = await getAuthContainer();

    expect(container.devAccount).toBeDefined();
    expect(await container.users.count()).toBe(1);

    const seeded = await container.users.findByEmail(container.devAccount!.email);
    expect(seeded?.role).toBe("APPROVER");
  });

  it("seeds an account that actually signs in", async () => {
    setNodeEnv("development");
    const container = await getAuthContainer();
    const { email, password } = container.devAccount!;

    await expect(container.authService.authenticate(email, password)).resolves.toBeDefined();
  });

  it("refuses to seed in production", async () => {
    setNodeEnv("production");
    const container = await getAuthContainer();

    expect(container.devAccount).toBeUndefined();
    expect(await container.users.count()).toBe(0);
  });

  it("does not seed in live mode", async () => {
    setNodeEnv("development");
    process.env.SECURITY_DATA_SOURCE = "live";
    resetAuthContainer();

    expect((await getAuthContainer()).devAccount).toBeUndefined();
  });

  it("does not seed onto the postgres driver", async () => {
    setNodeEnv("development");
    process.env.SECURITY_STORAGE = "postgres";
    resetAuthContainer();

    // Building the postgres container requires DATABASE_URL; the assertion is
    // that seeding is not attempted, so a throw about a missing URL is fine and
    // a seeded dev account is not.
    const container = await getAuthContainer().catch(() => null);
    expect(container?.devAccount).toBeUndefined();
  });
});
