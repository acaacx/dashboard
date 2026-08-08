import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  InvalidStatusReasonError,
  InvalidStatusTransitionError,
} from "@/domain/security/errors";
import { SESSION_COOKIE_NAME } from "@/lib/auth/cookie";
import { getAuthService, resetAuthContainer } from "@/lib/auth/container";

/**
 * The security service is mocked — its behaviour has its own suite — but the
 * session is real. Mocking the guard would assert that the action calls a mock,
 * and the property under test is "a viewer cannot change a status".
 */

const setFindingStatus = vi.fn();
let token: string | undefined;

// Partial: the auth container reads `configuredStorage()` from this same
// module, so replacing the whole thing would leave the session store unbuildable.
vi.mock("@/lib/security/container", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/security/container")>()),
  getSecurityService: async () => ({ setFindingStatus }),
}));

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) =>
      name === SESSION_COOKIE_NAME && token ? { value: token } : undefined,
  }),
}));

const { setFindingStatusAction } = await import(
  "@/app/dashboard/security/actions"
);

const PASSWORD = "correct horse battery staple";

async function signIn(email: string) {
  ({ token } = await (await getAuthService()).authenticate(email, PASSWORD));
}

beforeEach(async () => {
  setFindingStatus.mockReset();
  process.env.SECURITY_STORAGE = "memory";
  resetAuthContainer();
  token = undefined;

  const service = await getAuthService();
  await service.createUser("approver@example.com", PASSWORD, "APPROVER");
  await service.createUser("viewer@example.com", PASSWORD, "VIEWER");
  await signIn("approver@example.com");
});

afterEach(() => {
  resetAuthContainer();
  delete process.env.SECURITY_STORAGE;
});

describe("setFindingStatusAction", () => {
  it("returns the updated finding on success", async () => {
    setFindingStatus.mockResolvedValue({ id: "fnd_1", status: "ACCEPTED_RISK" });

    const result = await setFindingStatusAction(
      "fnd_1",
      "ACCEPTED_RISK",
      "Why.",
    );

    expect(result).toEqual({
      ok: true,
      finding: { id: "fnd_1", status: "ACCEPTED_RISK" },
    });
  });

  it("refuses RESOLVED before the service is consulted", async () => {
    const result = await setFindingStatusAction("fnd_1", "RESOLVED", "Why.");

    expect(result).toEqual({
      ok: false,
      code: "INVALID_STATUS_TRANSITION",
      message: expect.any(String),
    });
    expect(setFindingStatus).not.toHaveBeenCalled();
  });

  it("rejects a status that is not a finding status at all", async () => {
    const result = await setFindingStatusAction(
      "fnd_1",
      "DROP TABLE" as never,
      "Why.",
    );

    expect(result.ok).toBe(false);
    expect(setFindingStatus).not.toHaveBeenCalled();
  });

  it("reports a missing finding as NOT_FOUND", async () => {
    setFindingStatus.mockResolvedValue(null);

    const result = await setFindingStatusAction(
      "fnd_missing",
      "SUPPRESSED",
      "Why.",
    );

    expect(result).toEqual({
      ok: false,
      code: "NOT_FOUND",
      message: expect.any(String),
    });
  });

  it("passes a domain error's code and message through", async () => {
    setFindingStatus.mockRejectedValue(
      new InvalidStatusTransitionError("FALSE_POSITIVE", "SUPPRESSED"),
    );

    const result = await setFindingStatusAction("fnd_1", "SUPPRESSED", "Why.");

    expect(result).toMatchObject({
      ok: false,
      code: "INVALID_STATUS_TRANSITION",
    });
  });

  it("surfaces a reason error as its own code", async () => {
    setFindingStatus.mockRejectedValue(
      new InvalidStatusReasonError("A justification is required."),
    );

    const result = await setFindingStatusAction("fnd_1", "ACCEPTED_RISK", "");

    expect(result).toMatchObject({ ok: false, code: "INVALID_STATUS_REASON" });
  });

  it("never leaks an unexpected error's message", async () => {
    setFindingStatus.mockRejectedValue(
      new Error("connect ECONNREFUSED 10.0.0.4:5432 while querying findings"),
    );

    const result = await setFindingStatusAction(
      "fnd_1",
      "ACCEPTED_RISK",
      "Why.",
    );

    expect(result).toEqual({
      ok: false,
      code: "INTERNAL_ERROR",
      message: "The status change could not be applied.",
    });
    if (!result.ok) {
      expect(result.message).not.toContain("ECONNREFUSED");
      expect(result.message).not.toContain("10.0.0.4");
    }
  });

  it("signs the decision with the session's email", async () => {
    setFindingStatus.mockResolvedValue({ id: "fnd_1", status: "ACCEPTED_RISK" });

    await setFindingStatusAction("fnd_1", "ACCEPTED_RISK", "Why.");

    expect(setFindingStatus).toHaveBeenCalledWith(
      "fnd_1",
      "ACCEPTED_RISK",
      "Why.",
      { changedBy: "approver@example.com" },
    );
  });

  it("refuses a viewer before the service is consulted", async () => {
    await signIn("viewer@example.com");

    const result = await setFindingStatusAction(
      "fnd_1",
      "ACCEPTED_RISK",
      "Why.",
    );

    expect(result).toEqual({
      ok: false,
      code: "FORBIDDEN",
      message: expect.any(String),
    });
    expect(setFindingStatus).not.toHaveBeenCalled();
  });

  it("refuses a request with no session", async () => {
    token = undefined;

    const result = await setFindingStatusAction(
      "fnd_1",
      "ACCEPTED_RISK",
      "Why.",
    );

    expect(result).toEqual({
      ok: false,
      code: "UNAUTHENTICATED",
      message: expect.any(String),
    });
    expect(setFindingStatus).not.toHaveBeenCalled();
  });

  it("refuses a revoked session, so signing out ends the ability to decide", async () => {
    await (await getAuthService()).signOut(token!);

    const result = await setFindingStatusAction(
      "fnd_1",
      "ACCEPTED_RISK",
      "Why.",
    );

    expect(result).toMatchObject({ ok: false, code: "UNAUTHENTICATED" });
    expect(setFindingStatus).not.toHaveBeenCalled();
  });
});
