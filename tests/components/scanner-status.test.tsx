// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { ScannerHealth } from "@/domain/security/scan-run";
import { ScannerStatus } from "@/components/security/scanner-status";

const NOW = new Date("2026-08-10T12:00:00.000Z");

const health: ScannerHealth[] = [
  {
    scanner: "SEMGREP",
    status: "HEALTHY",
    lastScanAt: "2026-08-10T11:52:00.000Z",
    lastRunStatus: "COMPLETED",
    totalFindings: 6,
    runCount: 3,
  },
  {
    scanner: "TRIVY",
    status: "WARNING",
    lastScanAt: "2026-08-07T12:00:00.000Z",
    lastRunStatus: "COMPLETED",
    totalFindings: 7,
    runCount: 2,
  },
  {
    scanner: "CHECKOV",
    status: "FAILED",
    lastScanAt: "2026-08-10T11:50:00.000Z",
    lastRunStatus: "FAILED",
    runCount: 1,
    error: "Invalid SARIF document",
  },
  { scanner: "GITLEAKS", status: "NEVER_RUN", runCount: 0 },
];

describe("ScannerStatus", () => {
  it("labels each health state", () => {
    render(<ScannerStatus health={health} now={NOW} />);

    expect(screen.getByText("Semgrep")).toBeInTheDocument();
    expect(screen.getByText("Healthy")).toBeInTheDocument();
    expect(screen.getByText("Warning")).toBeInTheDocument();
    expect(screen.getByText("Never run")).toBeInTheDocument();
  });

  it("shows how long ago each scanner last reported", () => {
    render(<ScannerStatus health={health} now={NOW} />);

    expect(screen.getByText("· 8 minutes ago")).toBeInTheDocument();
    expect(screen.getByText("· 3 days ago")).toBeInTheDocument();
  });

  it("distinguishes a scanner that never ran from one that reported nothing", () => {
    render(<ScannerStatus health={health} now={NOW} />);

    // Gitleaks has no run at all: no timestamp, no finding count.
    expect(screen.getByText("· never scanned")).toBeInTheDocument();
    expect(screen.getByText("6 reported")).toBeInTheDocument();
  });

  it("renders the full scanner name rather than truncating it", () => {
    render(<ScannerStatus health={health} now={NOW} />);

    ["Semgrep", "Trivy", "Checkov", "Gitleaks"].forEach((name) => {
      expect(screen.getByText(name)).toBeInTheDocument();
    });
  });

  it("surfaces the failure reason for a failed scanner", () => {
    render(<ScannerStatus health={health} now={NOW} />);

    expect(screen.getByText("Invalid SARIF document")).toBeInTheDocument();
  });

  it("explains the empty state instead of rendering a blank panel", () => {
    render(<ScannerStatus health={[]} />);

    expect(
      screen.getByText("No scanners have reported yet."),
    ).toBeInTheDocument();
  });
});
