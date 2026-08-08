import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ForbiddenError, NotAuthenticatedError } from "@/domain/auth/errors";
import { SESSION_COOKIE_NAME } from "@/lib/auth/cookie";
import { getAuthService, resetAuthContainer } from "@/lib/auth/container";

/**
 * Exercised against the real in-memory container with only the Next.js cookie
 * jar stubbed. A mocked session store would assert that the guard calls a mock,
 * not that a viewer is refused.
 */

let token: string | undefined;

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) =>
      name === SESSION_COOKIE_NAME && token ? { value: token } : undefined,
  }),
}));

const PASSWORD = "correct horse battery staple";

describe("requireApprover", () => {
  beforeEach(async () => {
    process.env.SECURITY_STORAGE = "memory";
    resetAuthContainer();
    token = undefined;

    const service = await getAuthService();
    await service.createUser("approver@example.com", PASSWORD, "APPROVER");
    await service.createUser("viewer@example.com", PASSWORD, "VIEWER");
  });

  afterEach(() => {
    resetAuthContainer();
    delete process.env.SECURITY_STORAGE;
  });

  async function signIn(email: string) {
    ({ token } = await (await getAuthService()).authenticate(email, PASSWORD));
  }

  it("returns the approver", async () => {
    await signIn("approver@example.com");

    const { requireApprover } = await import("@/lib/auth/guards");
    const user = await requireApprover();

    expect(user.email).toBe("approver@example.com");
    expect(user.role).toBe("APPROVER");
    expect(user).not.toHaveProperty("passwordHash");
  });

  it("refuses a viewer", async () => {
    await signIn("viewer@example.com");

    const { requireApprover } = await import("@/lib/auth/guards");
    await expect(requireApprover()).rejects.toBeInstanceOf(ForbiddenError);
  });

  it("refuses a request with no session", async () => {
    const { requireApprover } = await import("@/lib/auth/guards");
    await expect(requireApprover()).rejects.toBeInstanceOf(
      NotAuthenticatedError,
    );
  });

  it("refuses a signed-out token, which is how revocation is real", async () => {
    await signIn("approver@example.com");
    await (await getAuthService()).signOut(token!);

    const { requireApprover } = await import("@/lib/auth/guards");
    await expect(requireApprover()).rejects.toBeInstanceOf(
      NotAuthenticatedError,
    );
  });
});
