import { randomUUID } from "node:crypto";

import type { ScannerType } from "@/domain/security/enums";
import {
  isSecurityDomainError,
  ScanIngestionError,
  toSafeErrorMessage,
} from "@/domain/security/errors";
import type { ScanContext, SecurityFinding } from "@/domain/security/finding";
import {
  emptyScanRunCounts,
  scanRunCounterKey,
  type ScanRun,
} from "@/domain/security/scan-run";
import type { AssetCorrelationService } from "@/domain/security/inventory";
import { NoopAssetCorrelationService } from "@/domain/security/inventory";
import type { ScannerAdapterRegistry } from "../adapters/scanner-adapter";
import {
  findResolvedFindings,
  reconcileFinding,
  resolveFinding,
  type ResolutionScope,
} from "../lifecycle";
import { recordSecurityEvent } from "../observability";
import type { SecurityFindingRepository } from "../repository/security-finding-repository";
import type { ScanRunRepository } from "../repository/scan-run-repository";

/**
 * Scan ingestion pipeline.
 *
 *   payload -> adapter -> normalized findings -> inventory enrichment
 *           -> in-payload dedup -> reconcile against store -> persist
 *           -> auto-resolve what the scan no longer reports -> scan run record
 *
 * The whole pipeline is one transaction-shaped unit: either a ScanRun lands as
 * COMPLETED with its findings, or as FAILED with a safe error message. It never
 * half-succeeds silently, because a scanner that appears healthy while dropping
 * findings is the worst possible failure mode for this dashboard.
 */

export interface ScanIngestionRequest {
  scanner: ScannerType;
  /** Declared format; advisory only — the adapter sniffs the payload anyway. */
  format?: "sarif" | "json";

  repositoryId?: string;
  repositoryName?: string;
  branch?: string;
  commitSha?: string;

  workflowRunId?: string;
  workflowRunUrl?: string;

  applicationId?: string;
  environment?: string;

  scannedAt?: string;

  /** The scanner's own output, already JSON-parsed. */
  results: unknown;

  /**
   * When false, findings this scan did not report are left untouched instead of
   * being auto-resolved. Use for partial or path-filtered scans, where absence
   * is not evidence of a fix.
   */
  autoResolveMissing?: boolean;
}

export interface ScanIngestionSummary {
  received: number;
  duplicatesInPayload: number;
  created: number;
  updated: number;
  reopened: number;
  resolved: number;
}

export interface ScanIngestionResult {
  scanRun: ScanRun;
  summary: ScanIngestionSummary;
  findings: SecurityFinding[];
}

export class ScanIngestionService {
  constructor(
    private readonly registry: ScannerAdapterRegistry,
    private readonly findings: SecurityFindingRepository,
    private readonly scanRuns: ScanRunRepository,
    private readonly correlation: AssetCorrelationService = new NoopAssetCorrelationService(),
  ) {}

  async ingest(request: ScanIngestionRequest): Promise<ScanIngestionResult> {
    const startedAt = new Date();
    const scannedAt = request.scannedAt ?? startedAt.toISOString();
    const runId = `run_${randomUUID()}`;

    const baseRun: ScanRun = {
      id: runId,
      scanner: request.scanner,
      repositoryId: request.repositoryId,
      repositoryName: request.repositoryName,
      branch: request.branch,
      commitSha: request.commitSha,
      workflowRunId: request.workflowRunId,
      workflowRunUrl: request.workflowRunUrl,
      status: "RUNNING",
      // Anchored on when the scan ran, not when we received it.
      startedAt: scannedAt,
      findings: emptyScanRunCounts(),
      totalFindings: 0,
    };

    await this.scanRuns.save(baseRun);

    recordSecurityEvent("scan.ingestion.started", {
      scanner: request.scanner,
      repository: request.repositoryName,
      runId,
    });

    try {
      const context: ScanContext = {
        scanner: request.scanner,
        repositoryId: request.repositoryId,
        repositoryName: request.repositoryName,
        branch: request.branch,
        commitSha: request.commitSha,
        workflowRunId: request.workflowRunId,
        workflowRunUrl: request.workflowRunUrl,
        applicationId: request.applicationId,
        environment: request.environment,
        scannedAt,
      };

      const adapter = this.registry.resolve(request.results, request.scanner);
      const parsed = await adapter.parse(request.results, {
        ...context,
        // The adapter that actually claimed the payload wins, so a mislabelled
        // upload is stored under the scanner that really produced it.
        scanner: adapter.scanner,
      });

      const enriched = await this.correlation.enrich(parsed);

      const { unique, duplicates } = dedupeByFingerprint(enriched);

      const existingByFingerprint = await this.findings.findManyByFingerprints(
        unique.map((finding) => finding.fingerprint),
      );

      const summary: ScanIngestionSummary = {
        received: parsed.length,
        duplicatesInPayload: duplicates,
        created: 0,
        updated: 0,
        reopened: 0,
        resolved: 0,
      };

      const toPersist: SecurityFinding[] = [];

      for (const incoming of unique) {
        const { finding, transition } = reconcileFinding(
          existingByFingerprint.get(incoming.fingerprint),
          incoming,
        );
        toPersist.push(finding);

        if (transition === "NEW") summary.created += 1;
        else if (transition === "REOPENED") summary.reopened += 1;
        else summary.updated += 1;
      }

      await this.findings.saveMany(toPersist);

      if (request.autoResolveMissing !== false) {
        const scope: ResolutionScope = {
          scanner: adapter.scanner,
          repositoryId: request.repositoryId,
          repositoryName: request.repositoryName,
          environment: request.environment,
        };

        const inScope = await this.findings.findByScope(scope);
        const seen = new Set(unique.map((finding) => finding.fingerprint));
        const nowResolved = findResolvedFindings(inScope, seen, scope);

        if (nowResolved.length > 0) {
          await this.findings.saveMany(
            nowResolved.map((finding) => resolveFinding(finding, scannedAt)),
          );
          summary.resolved = nowResolved.length;
        }
      }

      const completedAt = new Date();
      const counts = emptyScanRunCounts();
      // Scan-run counters describe what THIS scan reported, including findings
      // that already existed — that is what "Trivy found 12 issues" means.
      unique.forEach((finding) => {
        counts[scanRunCounterKey(finding.severity)] += 1;
      });

      const scanRun: ScanRun = {
        ...baseRun,
        scanner: adapter.scanner,
        status: "COMPLETED",
        completedAt: scannedAt,
        ingestedAt: completedAt.toISOString(),
        findings: counts,
        totalFindings: unique.length,
        durationSeconds: Math.max(
          0,
          Math.round(
            (completedAt.getTime() - startedAt.getTime()) / 1000,
          ),
        ),
      };
      await this.scanRuns.save(scanRun);

      recordSecurityEvent("scan.findings.processed", {
        scanner: adapter.scanner,
        runId,
        count: unique.length,
      });
      if (summary.created > 0) {
        recordSecurityEvent("scan.findings.created", {
          scanner: adapter.scanner,
          runId,
          count: summary.created,
        });
      }
      if (summary.reopened > 0) {
        recordSecurityEvent("scan.findings.reopened", {
          scanner: adapter.scanner,
          runId,
          count: summary.reopened,
        });
      }
      if (summary.resolved > 0) {
        recordSecurityEvent("scan.findings.resolved", {
          scanner: adapter.scanner,
          runId,
          count: summary.resolved,
        });
      }
      recordSecurityEvent("scan.ingestion.succeeded", {
        scanner: adapter.scanner,
        runId,
        durationSeconds: scanRun.durationSeconds,
      });

      return { scanRun, summary, findings: toPersist };
    } catch (error) {
      const failedAt = new Date();
      const message = toSafeErrorMessage(error);

      await this.scanRuns.save({
        ...baseRun,
        status: "FAILED",
        completedAt: scannedAt,
        ingestedAt: failedAt.toISOString(),
        durationSeconds: Math.max(
          0,
          Math.round((failedAt.getTime() - startedAt.getTime()) / 1000),
        ),
        error: message,
      });

      recordSecurityEvent("scan.ingestion.failed", {
        scanner: request.scanner,
        runId,
        // The message is domain-authored and payload-free by construction.
        reason: message,
      });
      recordSecurityEvent("scan.parser.error", {
        scanner: request.scanner,
        runId,
      });

      if (isSecurityDomainError(error)) throw error;
      throw new ScanIngestionError(message);
    }
  }
}

/**
 * Collapse findings that share a fingerprint inside a single payload.
 *
 * Real reports do this: Trivy lists the same CVE once per affected layer, and
 * Checkov repeats a policy across modules that resolve to one resource. Without
 * this, one scan would report the same problem several times and the counters
 * would drift from the table.
 */
export function dedupeByFingerprint(findings: readonly SecurityFinding[]): {
  unique: SecurityFinding[];
  duplicates: number;
} {
  const byFingerprint = new Map<string, SecurityFinding>();
  let duplicates = 0;

  for (const finding of findings) {
    const existing = byFingerprint.get(finding.fingerprint);
    if (!existing) {
      byFingerprint.set(finding.fingerprint, finding);
      continue;
    }
    duplicates += 1;
    // Keep the more severe of the two; otherwise ordering inside the payload
    // would decide the severity shown.
    if (severityWeight(finding) > severityWeight(existing)) {
      byFingerprint.set(finding.fingerprint, finding);
    }
  }

  return { unique: [...byFingerprint.values()], duplicates };
}

const WEIGHTS: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
  UNKNOWN: 0,
};

function severityWeight(finding: SecurityFinding): number {
  return WEIGHTS[finding.severity] ?? 0;
}
