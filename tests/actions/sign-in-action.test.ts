import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { MAX_LOGIN_ATTEMPTS } from "@/domain/auth/session";
import { getAuthService, resetAuthContainer } from "@/lib/auth/container";

/**
 * The action is tested through its real service and store, with only the
 * Next.js edges — the cookie jar and redirect — stubbed. Mocking the service
 * would assert that the action calls a mock, not that a wrong password is
 * refused.
 */

const cookieSet = vi.fn();
const redirected = vi.fn();

vi.mock("next/headers", () => ({
  cookies: async () => ({ set: cookieSet, get: () => undefined, delete: vi.fn() }),
}));

vi.mock("next/navigation", () => ({
  redirect: (url: string) => {
    redirected(url);
    throw new Error("NEXT_REDIRECT");
  },
}));

const PASSWORD = "correct horse battery staple";

function formData(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [key, value] of Object.entries(fields)) data.append(key, value);
  return data;
}

describe("signInAction", () => {
  beforeEach(async () => {
    process.env.SECURITY_STORAGE = "memory";
    resetAuthContainer();
    cookieSet.mockReset();
    redirected.mockReset();

    await (await getAuthService()).createUser("alice@example.com", PASSWORD, "APPROVER");
  });

  afterEach(() => {
    resetAuthContainer();
    delete process.env.SECURITY_STORAGE;
    vi.restoreAllMocks();
  });

  async function signIn(fields: Record<string, string>) {
    const { signInAction } = await import("@/app/login/actions");
    return signInAction({}, formData(fields)).catch((error: Error) => {
      if (error.message === "NEXT_REDIRECT") return { redirected: true } as const;
      throw error;
    });
  }

  it("sets a session cookie and redirects on success", async () => {
    await signIn({ email: "alice@example.com", password: PASSWORD });

    expect(cookieSet).toHaveBeenCalledOnce();
    expect(redirected).toHaveBeenCalledWith("/dashboard");
  });

  it("honours a safe next path", async () => {
    await signIn({ email: "alice@example.com", password: PASSWORD, next: "/dashboard/security" });
    expect(redirected).toHaveBeenCalledWith("/dashboard/security");
  });

  it("refuses to redirect off-site", async () => {
    await signIn({ email: "alice@example.com", password: PASSWORD, next: "//evil.example" });
    expect(redirected).toHaveBeenCalledWith("/dashboard");
  });

  it("returns an error and sets no cookie for a wrong password", async () => {
    const state = await signIn({ email: "alice@example.com", password: "wrong password!!" });

    expect(state).toMatchObject({ error: "Email or password is incorrect." });
    expect(cookieSet).not.toHaveBeenCalled();
    expect(redirected).not.toHaveBeenCalled();
  });

  it("gives an unknown email the identical message", async () => {
    const state = await signIn({ email: "ghost@example.com", password: PASSWORD });
    expect(state).toMatchObject({ error: "Email or password is incorrect." });
  });

  it("rejects a missing field without reaching the service", async () => {
    expect(await signIn({ email: "", password: "" })).toMatchObject({
      error: "Enter an email and a password.",
    });
  });

  it("surfaces the throttle", async () => {
    for (let attempt = 0; attempt < MAX_LOGIN_ATTEMPTS; attempt += 1) {
      await signIn({ email: "alice@example.com", password: "wrong password!!" });
    }

    const state = await signIn({ email: "alice@example.com", password: PASSWORD });
    expect(state).toMatchObject({ error: expect.stringContaining("Too many attempts") });
  });

  it("never echoes the submitted password", async () => {
    const state = await signIn({ email: "alice@example.com", password: "wrong password!!" });
    expect(JSON.stringify(state)).not.toContain("wrong password!!");
  });
});
