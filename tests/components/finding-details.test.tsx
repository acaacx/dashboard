// @vitest-environment jsdom
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { FindingDecision } from "@/domain/security/decision";
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
        canDecide
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
        canDecide
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
        canDecide
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

  it("locks the control for a viewer and says why", () => {
    const onApplyStatus = vi.fn();

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={onApplyStatus}
        canDecide={false}
      />,
    );

    expect(screen.getByLabelText(/change status to/i)).toBeDisabled();
    expect(screen.getByRole("button", { name: /apply/i })).toBeDisabled();
    expect(screen.getByText(/approver role is required/i)).toBeInTheDocument();
    expect(onApplyStatus).not.toHaveBeenCalled();
  });

  it("gives an approver a working control", async () => {
    const user = userEvent.setup();
    const onApplyStatus = vi.fn().mockResolvedValue({
      ok: true,
      finding: finding({ status: "SUPPRESSED" }),
    });

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={onApplyStatus}
        onStatusChanged={vi.fn()}
        canDecide
      />,
    );

    await user.selectOptions(
      screen.getByLabelText(/change status to/i),
      "SUPPRESSED",
    );
    await user.type(screen.getByLabelText(/reason/i), "Known noise.");
    await user.click(screen.getByRole("button", { name: /apply/i }));

    await waitFor(() =>
      expect(onApplyStatus).toHaveBeenCalledWith(
        "fnd_1",
        "SUPPRESSED",
        "Known noise.",
      ),
    );
  });

  it("shows who signed a decision", () => {
    render(
      <FindingDetails
        finding={finding({
          status: "ACCEPTED_RISK",
          statusReason: "Compensating control documented in RISK-88.",
          statusChangedAt: "2026-08-11T08:00:00.000Z",
          statusChangedBy: "approver@example.com",
        })}
        onClose={() => {}}
      />,
    );

    expect(screen.getByText(/approver@example\.com/)).toBeInTheDocument();
  });

  it("offers a way back in when the session expired mid-decision", async () => {
    const user = userEvent.setup();
    const onApplyStatus = vi.fn().mockResolvedValue({
      ok: false,
      code: "UNAUTHENTICATED",
      message: "Your session has expired. Sign in again to continue.",
    });

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={onApplyStatus}
        canDecide
      />,
    );

    await user.selectOptions(
      screen.getByLabelText(/change status to/i),
      "SUPPRESSED",
    );
    await user.type(screen.getByLabelText(/reason/i), "Known noise.");
    await user.click(screen.getByRole("button", { name: /apply/i }));

    const link = await screen.findByRole("link", { name: /sign in/i });
    expect(link).toHaveAttribute("href", "/login");
  });
});

function historyEntry(
  overrides: Partial<FindingDecision> = {},
): FindingDecision {
  return {
    id: "dec_1",
    findingId: "fnd_1",
    fromStatus: "OPEN",
    toStatus: "ACCEPTED_RISK",
    reason: "Mitigated by the WAF rule shipped in PR 412.",
    decidedBy: "approver@example.com",
    decidedAt: "2026-08-12T10:00:00.000Z",
    ...overrides,
  };
}

describe("FindingDetails decision history", () => {
  it("renders no timeline when no loader is supplied", () => {
    render(<FindingDetails finding={finding()} onClose={() => {}} />);

    expect(screen.queryByText("Decision history")).toBeNull();
  });

  it("shows a loading state, then the timeline", async () => {
    const loadHistory = vi
      .fn()
      .mockResolvedValue([
        historyEntry({ id: "dec_2" }),
        historyEntry({
          id: "dec_1",
          fromStatus: "ACCEPTED_RISK",
          toStatus: "OPEN",
          reason: undefined,
          decidedBy: "second@example.com",
          decidedAt: "2026-08-11T10:00:00.000Z",
        }),
      ]);

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        loadHistory={loadHistory}
      />,
    );

    expect(screen.getByText(/loading decision history/i)).toBeInTheDocument();

    // Await the expected call, never the last render: the debounce-race rule.
    await waitFor(() => expect(loadHistory).toHaveBeenCalledWith("fnd_1"));
    expect(
      await screen.findByText("Mitigated by the WAF rule shipped in PR 412."),
    ).toBeInTheDocument();
    expect(screen.getByText("approver@example.com")).toBeInTheDocument();
    expect(screen.getByText("second@example.com")).toBeInTheDocument();
  });

  it("explains an empty history rather than implying none happened", async () => {
    const loadHistory = vi.fn().mockResolvedValue([]);

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        loadHistory={loadHistory}
      />,
    );

    expect(
      await screen.findByText("Earlier decisions were not recorded."),
    ).toBeInTheDocument();
  });

  it("reports a failed load without disabling the decision form", async () => {
    const loadHistory = vi.fn().mockRejectedValue(new Error("boom"));

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={vi.fn()}
        canDecide
        loadHistory={loadHistory}
      />,
    );

    expect(
      await screen.findByText("Decision history could not be loaded."),
    ).toBeInTheDocument();
    // The audit view is not a gate: the form is still usable.
    expect(screen.getByLabelText(/change status to/i)).toBeInTheDocument();
  });

  it("refetches when the finding's decision snapshot changes", async () => {
    const loadHistory = vi.fn().mockResolvedValue([]);

    const { rerender } = render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        loadHistory={loadHistory}
      />,
    );
    await waitFor(() => expect(loadHistory).toHaveBeenCalledTimes(1));

    // What handleStatusChanged does after a successful decision: the drawer
    // receives the stored finding, whose statusChangedAt moved.
    rerender(
      <FindingDetails
        finding={finding({
          status: "ACCEPTED_RISK",
          statusChangedAt: "2026-08-12T11:00:00.000Z",
        })}
        onClose={() => {}}
        loadHistory={loadHistory}
      />,
    );

    await waitFor(() => expect(loadHistory).toHaveBeenCalledTimes(2));
  });
});
