// @vitest-environment jsdom
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SecurityFinding } from "@/domain/security/finding";
import { FindingDetails } from "@/components/security/finding-details";

function finding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: "fnd_1",
    fingerprint: "fp1",
    scanner: "SEMGREP",
    category: "SAST",
    severity: "CRITICAL",
    title: "SQL injection in the orders endpoint",
    repositoryName: "payment-service",
    status: "OPEN",
    firstDetectedAt: "2026-07-14T09:12:33.000Z",
    lastDetectedAt: "2026-08-10T09:12:33.000Z",
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("FindingDetails decision section", () => {
  it("offers the human decisions and never manual RESOLVED", () => {
    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={vi.fn()}
        onStatusChanged={vi.fn()}
      />,
    );

    const select = screen.getByLabelText(/change status to/i);
    const options = Array.from(select.querySelectorAll("option")).map(
      (option) => option.textContent,
    );

    expect(options).toEqual(
      expect.arrayContaining(["Accepted risk", "False positive", "Suppressed"]),
    );
    expect(options).not.toContain("Resolved");
  });

  it("shows an existing justification", () => {
    render(
      <FindingDetails
        finding={finding({
          status: "ACCEPTED_RISK",
          statusReason: "Compensating control documented in RISK-88.",
          statusChangedAt: "2026-08-11T08:00:00.000Z",
        })}
        onClose={() => {}}
      />,
    );

    expect(
      screen.getByText("Compensating control documented in RISK-88."),
    ).toBeTruthy();
  });

  it("sends the chosen status and reason, then reports the updated finding", async () => {
    const user = userEvent.setup();
    const updated = finding({
      status: "ACCEPTED_RISK",
      statusReason: "WAF rule.",
    });
    const onApplyStatus = vi
      .fn()
      .mockResolvedValue({ ok: true, finding: updated });
    const onStatusChanged = vi.fn();

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={onApplyStatus}
        onStatusChanged={onStatusChanged}
      />,
    );

    await user.selectOptions(
      screen.getByLabelText(/change status to/i),
      "ACCEPTED_RISK",
    );
    await user.type(screen.getByLabelText(/reason/i), "WAF rule.");
    await user.click(screen.getByRole("button", { name: /apply/i }));

    await waitFor(() =>
      expect(onApplyStatus).toHaveBeenCalledWith(
        "fnd_1",
        "ACCEPTED_RISK",
        "WAF rule.",
      ),
    );
    expect(onStatusChanged).toHaveBeenCalledWith(updated);
  });

  it("renders a failure inline and keeps the typed reason", async () => {
    const user = userEvent.setup();
    const onApplyStatus = vi.fn().mockResolvedValue({
      ok: false,
      code: "INVALID_STATUS_REASON",
      message: "A justification is required.",
    });
    const onStatusChanged = vi.fn();

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={onApplyStatus}
        onStatusChanged={onStatusChanged}
      />,
    );

    await user.selectOptions(
      screen.getByLabelText(/change status to/i),
      "SUPPRESSED",
    );
    await user.type(screen.getByLabelText(/reason/i), "Noisy rule.");
    await user.click(screen.getByRole("button", { name: /apply/i }));

    await waitFor(() =>
      expect(screen.getByText("A justification is required.")).toBeTruthy(),
    );
    expect(onStatusChanged).not.toHaveBeenCalled();
    expect(screen.getByLabelText(/reason/i)).toHaveValue("Noisy rule.");
  });

  it("hides the form entirely when no action is supplied", () => {
    render(<FindingDetails finding={finding()} onClose={() => {}} />);

    expect(screen.queryByLabelText(/change status to/i)).toBeNull();
  });
});
