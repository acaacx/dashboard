import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  InvalidStatusReasonError,
  InvalidStatusTransitionError,
} from "@/domain/security/errors";

const setFindingStatus = vi.fn();

vi.mock("@/lib/security/container", () => ({
  getSecurityService: async () => ({ setFindingStatus }),
}));

const { setFindingStatusAction } = await import(
  "@/app/dashboard/security/actions"
);

beforeEach(() => {
  setFindingStatus.mockReset();
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
});
