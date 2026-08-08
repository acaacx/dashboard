// @vitest-environment jsdom
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Page, SecurityFinding } from "@/domain/security/finding";
import { FindingsTable } from "@/components/security/findings-table";
import type { FilterOptions } from "@/lib/security/repository/security-finding-repository";

const refresh = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh }),
}));

const filterOptions: FilterOptions = {
  repositories: ["payment-service", "user-service"],
  environments: ["production", "staging"],
  scanners: ["SEMGREP", "TRIVY", "CHECKOV", "GITLEAKS"],
  categories: ["SAST", "SCA", "SECRET", "IAC"],
};

function finding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: "fnd_1",
    fingerprint: "fp1",
    scanner: "GITLEAKS",
    category: "SECRET",
    severity: "CRITICAL",
    title: "Hardcoded AWS access key",
    repositoryName: "payment-service",
    environment: "production",
    file: "deploy/legacy/aws.cfg",
    startLine: 27,
    ruleId: "aws-access-token",
    status: "OPEN",
    firstDetectedAt: "2026-07-14T09:12:33.000Z",
    lastDetectedAt: "2026-08-10T09:12:33.000Z",
    ...overrides,
  };
}

function page(items: SecurityFinding[]): Page<SecurityFinding> {
  return {
    items,
    total: items.length,
    page: 1,
    pageSize: 25,
    totalPages: 1,
  };
}

const initialResult = page([
  finding(),
  finding({
    id: "fnd_2",
    fingerprint: "fp2",
    scanner: "TRIVY",
    category: "SCA",
    severity: "MEDIUM",
    title: "lodash: prototype pollution",
    repositoryName: "frontend-app",
    environment: "staging",
    cve: "CVE-2026-3456",
    packageName: "lodash",
    packageVersion: "4.17.20",
    fixedVersion: "4.17.21",
    ruleId: undefined,
  }),
]);

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  refresh.mockReset();
  fetchMock = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => page([]),
  });
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function currentQuery(): URLSearchParams | undefined {
  const url = fetchMock.mock.calls.at(-1)?.[0] as string | undefined;
  return url ? new URL(url, "http://localhost").searchParams : undefined;
}

/** The query string of the most recent /api/security/findings request. */
async function lastQuery(): Promise<URLSearchParams> {
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
  return currentQuery()!;
}

/**
 * Wait until the most recent request matches an expectation.
 *
 * Filter changes are debounced, so after two interactions the newest request
 * may not have fired yet. Asserting on "whatever the last call happens to be"
 * races under load; this polls until the expected state actually arrives.
 */
async function waitForQuery(
  assertion: (params: URLSearchParams) => void,
): Promise<void> {
  await waitFor(() => {
    const params = currentQuery();
    expect(params).toBeDefined();
    assertion(params!);
  });
}

describe("FindingsTable rendering", () => {
  it("renders one row per finding with the normalized columns", () => {
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    const rows = screen.getAllByRole("button", { name: /./ }).filter(
      (element) => element.tagName === "TR",
    );
    expect(rows).toHaveLength(2);

    const first = rows[0];
    expect(within(first).getByText("Hardcoded AWS access key")).toBeInTheDocument();
    expect(within(first).getByText("Critical")).toBeInTheDocument();
    expect(within(first).getByText("Gitleaks")).toBeInTheDocument();
    expect(within(first).getByText("Secret")).toBeInTheDocument();
    expect(within(first).getByText("payment-service")).toBeInTheDocument();
    expect(within(first).getByText("production")).toBeInTheDocument();
    expect(within(first).getByText("Open")).toBeInTheDocument();
    expect(within(first).getByText("2026-07-14")).toBeInTheDocument();
    expect(within(first).getByText("2026-08-10")).toBeInTheDocument();
  });

  it("shows the secondary identifier, preferring CVE over rule id", () => {
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    expect(screen.getByText("aws-access-token")).toBeInTheDocument();
    expect(screen.getByText("CVE-2026-3456")).toBeInTheDocument();
  });

  it("reports the result range and does not fetch on first render", () => {
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    expect(screen.getByText("1–2 of 2")).toBeInTheDocument();
    // The server already supplied this page.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("renders an empty state when there are no findings", () => {
    render(<FindingsTable initialResult={page([])} filterOptions={filterOptions} />);

    expect(
      screen.getByText("No findings match these filters."),
    ).toBeInTheDocument();
  });
});

describe("FindingsTable filtering", () => {
  it("sends severity filters to the server", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    await user.click(screen.getByRole("button", { name: "Critical" }));

    const params = await lastQuery();
    expect(params.get("severity")).toBe("CRITICAL");
    expect(params.get("page")).toBeNull(); // reset to page 1
  });

  it("accumulates multiple severities", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    await user.click(screen.getByRole("button", { name: "Critical" }));
    await user.click(screen.getByRole("button", { name: "High" }));

    await waitForQuery((params) =>
      expect(params.get("severity")).toBe("CRITICAL,HIGH"),
    );
  });

  it("toggles a severity off again", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    const critical = screen.getByRole("button", { name: "Critical" });
    await user.click(critical);
    await waitFor(() => expect(critical).toHaveAttribute("aria-pressed", "true"));

    await user.click(critical);
    await waitFor(() => expect(critical).toHaveAttribute("aria-pressed", "false"));

    const params = await lastQuery();
    expect(params.get("severity")).toBeNull();
  });

  it("sends scanner, category, repository and environment filters", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    await user.selectOptions(screen.getByLabelText("Scanner"), "TRIVY");
    await user.selectOptions(screen.getByLabelText("Repository"), "user-service");

    await waitForQuery((params) => {
      expect(params.get("scanner")).toBe("TRIVY");
      expect(params.get("repository")).toBe("user-service");
    });
  });

  it("searches server-side rather than filtering the current page", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    await user.type(screen.getByRole("searchbox"), "CVE-2026");

    const params = await lastQuery();
    expect(params.get("search")).toBe("CVE-2026");
  });

  it("defaults to open findings and lets other statuses be added", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    expect(screen.getByRole("button", { name: "Open" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );

    await user.click(screen.getByRole("button", { name: "Resolved" }));

    await waitForQuery((params) =>
      expect(params.get("status")).toBe("OPEN,RESOLVED"),
    );
  });

  it("resets every filter", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    await user.click(screen.getByRole("button", { name: "Critical" }));
    await user.click(await screen.findByRole("button", { name: "Reset filters" }));

    await waitForQuery((params) => {
      expect(params.get("severity")).toBeNull();
      expect(params.get("status")).toBe("OPEN");
    });
  });

  it("changes sort direction on repeated header clicks", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    await user.click(screen.getByRole("button", { name: /First detected/ }));
    await waitForQuery((params) => {
      expect(params.get("sortBy")).toBe("firstDetectedAt");
      expect(params.get("sortDirection")).toBe("desc");
    });

    await user.click(screen.getByRole("button", { name: /First detected/ }));
    await waitForQuery((params) => {
      expect(params.get("sortBy")).toBe("firstDetectedAt");
      expect(params.get("sortDirection")).toBe("asc");
    });
  });
});

describe("FindingsTable detail drawer", () => {
  it("opens a finding's details when its row is activated", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    await user.click(screen.getByText("lodash: prototype pollution"));

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("CVE-2026-3456")).toBeInTheDocument();
    expect(within(dialog).getByText("4.17.20")).toBeInTheDocument();
    expect(within(dialog).getByText("4.17.21")).toBeInTheDocument();
  });

  it("states plainly when the scanner supplied no remediation", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    await user.click(screen.getByText("Hardcoded AWS access key"));

    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByText(
        /Gitleaks did not provide remediation guidance/i,
      ),
    ).toBeInTheDocument();
  });

  it("closes on Escape", async () => {
    const user = userEvent.setup();
    render(
      <FindingsTable initialResult={initialResult} filterOptions={filterOptions} />,
    );

    await user.click(screen.getByText("Hardcoded AWS access key"));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();

    await user.keyboard("{Escape}");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("opens preselected finding passed from a deep link", async () => {
    render(
      <FindingsTable
        initialResult={initialResult}
        filterOptions={filterOptions}
        initialSelected={finding()}
      />,
    );

    expect(await screen.findByRole("dialog")).toBeInTheDocument();
  });

  it("refetches the current query and refreshes the page after a status change", async () => {
    const user = userEvent.setup();
    const accepted = finding({
      status: "ACCEPTED_RISK",
      statusReason: "WAF rule.",
    });
    const setStatusAction = vi
      .fn()
      .mockResolvedValue({ ok: true, finding: accepted });

    render(
      <FindingsTable
        initialResult={initialResult}
        filterOptions={filterOptions}
        setStatusAction={setStatusAction}
        canDecide
      />,
    );

    await user.click(screen.getByText("Hardcoded AWS access key"));

    await user.selectOptions(
      screen.getByLabelText(/change status to/i),
      "ACCEPTED_RISK",
    );
    await user.type(screen.getByLabelText(/reason/i), "WAF rule.");
    await user.click(screen.getByRole("button", { name: /apply/i }));

    // The drawer now shows the returned finding, not an optimistic guess.
    await waitFor(() => expect(screen.getByText("WAF rule.")).toBeTruthy());

    // The current query re-runs, so a finding that left the OPEN filter goes away.
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(refresh).toHaveBeenCalled();
  });

  it("passes the decision permission down to the drawer", async () => {
    const user = userEvent.setup();

    const { unmount } = render(
      <FindingsTable
        initialResult={initialResult}
        filterOptions={filterOptions}
        setStatusAction={vi.fn()}
      />,
    );

    await user.click(screen.getByText("Hardcoded AWS access key"));
    // No canDecide: a caller that did not ask the guard gets the locked control.
    expect(screen.getByLabelText(/change status to/i)).toBeDisabled();

    unmount();

    render(
      <FindingsTable
        initialResult={initialResult}
        filterOptions={filterOptions}
        setStatusAction={vi.fn()}
        canDecide
      />,
    );

    await user.click(screen.getByText("Hardcoded AWS access key"));
    expect(screen.getByLabelText(/change status to/i)).toBeEnabled();
  });
});
