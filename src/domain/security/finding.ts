import type {
  FindingCategory,
  FindingStatus,
  ScannerType,
  Severity,
} from "./enums";

/**
 * The normalized security finding.
 *
 * Everything downstream of an adapter speaks this shape and only this shape.
 * No scanner-specific field ever leaks past the adapter boundary; anything a
 * scanner reports that has no home here goes into `metadata` and is treated as
 * untrusted text by the UI.
 */
export interface SecurityFinding {
  id: string;

  /**
   * Deterministic identity of the finding across scans.
   * @see generateFindingFingerprint
   */
  fingerprint: string;

  scanner: ScannerType;
  category: FindingCategory;
  severity: Severity;

  title: string;
  description?: string;

  // --- Inventory correlation keys (all optional; filled in by ingestion
  // context today, by the inventory service later). ---
  repositoryId?: string;
  repositoryName?: string;

  branch?: string;
  commitSha?: string;

  applicationId?: string;

  environment?: string;

  // --- Code location ---
  file?: string;
  startLine?: number;
  endLine?: number;

  // --- Dependency / package findings ---
  packageName?: string;
  packageVersion?: string;
  fixedVersion?: string;

  // --- Classification ---
  cve?: string;
  cwe?: string;

  ruleId?: string;

  /**
   * Non-Azure resource identifier, e.g. a Terraform address such as
   * `azurerm_storage_account.public`, a Kubernetes object, or a container image.
   * Extension beyond the base spec: the findings table renders a
   * "Repository / Resource" column and IaC findings have no repository-level
   * location that is precise enough on its own.
   */
  resource?: string;

  // --- Azure correlation ---
  azureResourceId?: string;
  subscriptionId?: string;
  resourceGroup?: string;

  status: FindingStatus;

  firstDetectedAt: string;
  lastDetectedAt: string;

  resolvedAt?: string;

  /**
   * Why a human set the current status. Present only when a person decided:
   * scanners never supply it and `reconcileFinding` refuses to accept one from
   * an adapter. Free text, untrusted, rendered as text and never as HTML.
   */
  statusReason?: string;

  /** ISO-8601 UTC instant of the last manual status change. */
  statusChangedAt?: string;

  /**
   * Remediation text as reported by the scanner. Never synthesised: if the
   * scanner did not supply guidance this stays undefined and the UI says so.
   */
  remediation?: string;

  sourceUrl?: string;

  metadata?: Record<string, unknown>;
}

/**
 * The context in which a scan ran. Supplied by the ingestion caller (CI), not
 * by the scanner output, because scanner output rarely knows which repository,
 * branch or environment it was pointed at.
 */
export interface ScanContext {
  scanner: ScannerType;

  repositoryId?: string;
  repositoryName?: string;

  branch?: string;
  commitSha?: string;

  workflowRunId?: string;
  workflowRunUrl?: string;

  applicationId?: string;
  environment?: string;

  scannedAt: string;
}

/** Server-side filter set. Every field is optional and AND-combined. */
export interface FindingFilters {
  severity?: Severity[];
  scanner?: ScannerType[];
  category?: FindingCategory[];
  status?: FindingStatus[];
  repository?: string[];
  environment?: string[];
  /** Free-text search across title, CVE, CWE, repository, file, resource, rule id. */
  search?: string;
  /** Only findings whose lastDetectedAt is at or after this ISO timestamp. */
  detectedSince?: string;
}

export interface FindingQuery extends FindingFilters {
  page?: number;
  pageSize?: number;
  sortBy?: "severity" | "lastDetectedAt" | "firstDetectedAt" | "title";
  sortDirection?: "asc" | "desc";
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

export type SeverityCounts = Record<Severity, number>;

export interface FindingStatistics {
  totalOpen: number;
  totalResolved: number;
  totalAcceptedRisk: number;
  totalFalsePositive: number;
  totalSuppressed: number;
  /** All findings matching the filter regardless of status. */
  total: number;

  /** Open findings only, by severity. Resolved findings are never counted here. */
  bySeverity: SeverityCounts;
  byScanner: Record<string, number>;
  byCategory: Record<string, number>;
  byRepository: Record<string, number>;
  byEnvironment: Record<string, number>;

  /** Findings first detected inside the requested window. */
  newFindings: number;
  /** Findings resolved inside the requested window. */
  resolvedFindings: number;

  /**
   * Mean time to remediate, in hours, over findings resolved in the window.
   * Undefined when nothing was resolved — never zero-filled, because zero
   * would read as "instant remediation".
   */
  meanTimeToRemediateHours?: number;
}

export interface TrendPoint {
  /** YYYY-MM-DD */
  date: string;
  open: number;
  new: number;
  resolved: number;
}

export interface RepositorySecuritySummary {
  repositoryName: string;
  repositoryId?: string;
  openFindings: number;
  bySeverity: SeverityCounts;
  /** Per-scanner outcome derived from scan runs and open findings. */
  scanners: Array<{
    scanner: ScannerType;
    status: "PASSED" | "FAILED" | "NEVER_RUN";
    openFindings: number;
    lastScanAt?: string;
  }>;
}

export function emptySeverityCounts(): SeverityCounts {
  return {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
    UNKNOWN: 0,
  };
}
