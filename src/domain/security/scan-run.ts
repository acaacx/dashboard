import type { ScannerType, Severity } from "./enums";

export const SCAN_RUN_STATUSES = ["RUNNING", "COMPLETED", "FAILED"] as const;

export type ScanRunStatus = (typeof SCAN_RUN_STATUSES)[number];

export interface ScanRunFindingCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/**
 * One execution of one scanner against one target. Scanner health on the
 * dashboard is derived entirely from these records — never from the findings
 * themselves, because "no findings" and "scanner never ran" must not look alike.
 */
export interface ScanRun {
  id: string;

  scanner: ScannerType;

  repositoryId?: string;
  repositoryName?: string;

  branch?: string;
  commitSha?: string;

  workflowRunId?: string;
  workflowRunUrl?: string;

  status: ScanRunStatus;

  /**
   * When the SCAN ran, taken from the ingestion request's `scannedAt`.
   * Not when the dashboard received it — a report uploaded an hour late must
   * not make a scanner look freshly run.
   */
  startedAt: string;
  completedAt?: string;

  /** When the dashboard normalized and stored this report. */
  ingestedAt?: string;

  findings: ScanRunFindingCounts;

  totalFindings: number;

  /**
   * Seconds spent normalizing and persisting the report. This is ingestion
   * cost, not how long the scanner itself took — scanner output does not
   * report its own duration.
   */
  durationSeconds?: number;

  /** Present when status is FAILED. Safe, short message — never a raw payload. */
  error?: string;
}

export type ScannerHealthStatus = "HEALTHY" | "WARNING" | "FAILED" | "NEVER_RUN";

export interface ScannerHealth {
  scanner: ScannerType;
  status: ScannerHealthStatus;
  lastScanAt?: string;
  lastRunId?: string;
  lastRunStatus?: ScanRunStatus;
  totalFindings?: number;
  /** Scan runs recorded for this scanner in the health window. */
  runCount: number;
  /** Populated when the most recent run failed. */
  error?: string;
}

export function emptyScanRunCounts(): ScanRunFindingCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/**
 * Bucket a severity into the ScanRun counter shape. UNKNOWN is folded into
 * `info` so the counters always sum to totalFindings.
 */
export function scanRunCounterKey(
  severity: Severity,
): keyof ScanRunFindingCounts {
  switch (severity) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "info";
  }
}

export interface ScanRunQuery {
  scanner?: ScannerType[];
  repositoryName?: string[];
  status?: ScanRunStatus[];
  limit?: number;
}
