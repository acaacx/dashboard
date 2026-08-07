import type { ScannerType } from "@/domain/security/enums";
import type { SecurityService } from "../services/security-service";
import type {
  ScanIngestionRequest,
  ScanIngestionService,
} from "../services/scan-ingestion-service";
import {
  checkovInfrastructure,
  gitleaksPaymentService,
  MOCK_REPOSITORIES,
  semgrepCheckoutService,
  semgrepPaymentService,
  semgrepUserService,
  trivyFrontendApp,
  trivyOrderService,
  trivyUserService,
} from "./mock-scan-payloads";

/**
 * ============================ MOCK DATA ============================
 * Seeds the development dashboard by replaying fabricated scanner output
 * through the real ingestion pipeline.
 * ==================================================================
 *
 * Three passes, so the dashboard has history rather than a flat snapshot:
 *
 *  1. T-21d  full payloads including findings that were later fixed
 *  2. T-10d  those findings are gone -> the pipeline auto-resolves them,
 *            which is what populates the trend chart and MTTR
 *  3. T-now  a fresh run minutes ago, so scanner health reads HEALTHY
 *
 * Nothing is written by hand: every finding here went through an adapter,
 * a fingerprint and a lifecycle reconciliation.
 */

const DAY_MS = 86_400_000;
const MINUTE_MS = 60_000;

interface MockScanDefinition {
  scanner: ScannerType;
  profile: (typeof MOCK_REPOSITORIES)[keyof typeof MOCK_REPOSITORIES];
  build: (includeStale: boolean) => unknown;
  /** Minutes before "now" for the freshest pass — drives Scanner Status. */
  freshOffsetMinutes: number;
}

const MOCK_SCANS: MockScanDefinition[] = [
  {
    scanner: "SEMGREP",
    profile: MOCK_REPOSITORIES.payment,
    build: semgrepPaymentService,
    freshOffsetMinutes: 8,
  },
  {
    scanner: "SEMGREP",
    profile: MOCK_REPOSITORIES.user,
    build: semgrepUserService,
    freshOffsetMinutes: 8,
  },
  {
    scanner: "SEMGREP",
    profile: MOCK_REPOSITORIES.checkout,
    build: semgrepCheckoutService,
    freshOffsetMinutes: 8,
  },
  {
    scanner: "GITLEAKS",
    profile: MOCK_REPOSITORIES.payment,
    build: gitleaksPaymentService,
    freshOffsetMinutes: 7,
  },
  {
    scanner: "CHECKOV",
    profile: MOCK_REPOSITORIES.infrastructure,
    build: checkovInfrastructure,
    freshOffsetMinutes: 10,
  },
  {
    scanner: "TRIVY",
    profile: MOCK_REPOSITORIES.user,
    build: trivyUserService,
    freshOffsetMinutes: 9,
  },
  {
    scanner: "TRIVY",
    profile: MOCK_REPOSITORIES.order,
    build: trivyOrderService,
    freshOffsetMinutes: 9,
  },
  {
    scanner: "TRIVY",
    profile: MOCK_REPOSITORIES.frontend,
    build: trivyFrontendApp,
    freshOffsetMinutes: 9,
  },
];

function toRequest(
  definition: MockScanDefinition,
  scannedAt: Date,
  includeStale: boolean,
  runSuffix: string,
): ScanIngestionRequest {
  return {
    scanner: definition.scanner,
    repositoryId: definition.profile.repositoryId,
    repositoryName: definition.profile.repositoryName,
    branch: definition.profile.branch,
    commitSha: definition.profile.commitSha,
    applicationId: definition.profile.applicationId,
    environment: definition.profile.environment,
    workflowRunId: `mock-${definition.scanner.toLowerCase()}-${definition.profile.repositoryName}-${runSuffix}`,
    workflowRunUrl: "https://github.com/example/mock/actions/runs/1",
    scannedAt: scannedAt.toISOString(),
    results: definition.build(includeStale),
  };
}

export interface SeedResult {
  scansIngested: number;
  findingsStored: number;
}

export async function seedMockData(
  ingestion: ScanIngestionService,
  security: SecurityService,
  now: Date = new Date(),
): Promise<SeedResult> {
  const historical = new Date(now.getTime() - 21 * DAY_MS);
  const midpoint = new Date(now.getTime() - 10 * DAY_MS);

  let scansIngested = 0;

  for (const definition of MOCK_SCANS) {
    await ingestion.ingest(toRequest(definition, historical, true, "t21"));
    scansIngested += 1;
  }

  for (const definition of MOCK_SCANS) {
    await ingestion.ingest(toRequest(definition, midpoint, false, "t10"));
    scansIngested += 1;
  }

  for (const definition of MOCK_SCANS) {
    const scannedAt = new Date(
      now.getTime() - definition.freshOffsetMinutes * MINUTE_MS,
    );
    await ingestion.ingest(toRequest(definition, scannedAt, false, "fresh"));
    scansIngested += 1;
  }

  // One finding is deliberately accepted rather than fixed, so the Security
  // page's "Accepted Risk" card and the status filter have real data behind
  // them instead of a hardcoded zero.
  await acceptOneRisk(security);

  const page = await security.getFindings({ pageSize: 200 });

  return { scansIngested, findingsStored: page.total };
}

async function acceptOneRisk(security: SecurityService): Promise<void> {
  const page = await security.getFindings({
    scanner: ["CHECKOV"],
    status: ["OPEN"],
    pageSize: 200,
  });

  const target = page.items.find(
    (finding) => finding.ruleId === "CKV_AZURE_112",
  );
  if (target) {
    await security.setFindingStatus(target.id, "ACCEPTED_RISK");
  }
}
