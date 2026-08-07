import type { ScanContext, SecurityFinding } from "@/domain/security/finding";
import type { FindingCategory, Severity } from "@/domain/security/enums";
import {
  findingIdFromFingerprint,
  generateFindingFingerprint,
  type FingerprintInput,
} from "../normalization/fingerprint";

/**
 * Small helpers shared by the native-JSON adapters.
 *
 * Every accessor here is total: it takes `unknown` and returns a usable value
 * or `undefined`. Adapters therefore never index into a payload optimistically,
 * which is what keeps a malformed scanner report from throwing.
 */

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function str(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

export function int(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return Math.trunc(parsed);
  }
  return undefined;
}

export function positiveInt(value: unknown): number | undefined {
  const parsed = int(value);
  return parsed !== undefined && parsed > 0 ? parsed : undefined;
}

export function arr(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function strArray(value: unknown): string[] {
  if (typeof value === "string") {
    const single = str(value);
    return single ? [single] : [];
  }
  return arr(value)
    .map(str)
    .filter((entry): entry is string => entry !== undefined);
}

const CWE_PATTERN = /\bCWE-\d+\b/i;
const CVE_PATTERN = /\b(?:CVE-\d{4}-\d{4,7}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})\b/i;

/** Pull the first `CWE-nnn` token out of any of the candidates. */
export function extractCwe(...candidates: unknown[]): string | undefined {
  for (const candidate of candidates) {
    for (const text of strArray(candidate)) {
      const match = CWE_PATTERN.exec(text);
      if (match) return match[0].toUpperCase();
    }
  }
  return undefined;
}

/** Pull the first CVE or GHSA identifier out of any of the candidates. */
export function extractCve(...candidates: unknown[]): string | undefined {
  for (const candidate of candidates) {
    for (const text of strArray(candidate)) {
      const match = CVE_PATTERN.exec(text);
      if (match) return match[0].toUpperCase();
    }
  }
  return undefined;
}

/** Titles feed table cells and tooltips; keep them single-line and bounded. */
export function normalizeTitle(value: string): string {
  return value.replace(/\s+/g, " ").trim().slice(0, 300);
}

/**
 * Drop keys whose value is undefined so `metadata` does not serialize a wall
 * of nulls into API responses.
 */
export function compactMetadata(
  metadata: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const entries = Object.entries(metadata).filter(
    ([, value]) =>
      value !== undefined &&
      value !== null &&
      !(Array.isArray(value) && value.length === 0),
  );
  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}

export interface BuildFindingInput {
  category: FindingCategory;
  severity: Severity;
  title: string;
  description?: string;
  file?: string;
  startLine?: number;
  endLine?: number;
  packageName?: string;
  packageVersion?: string;
  fixedVersion?: string;
  cve?: string;
  cwe?: string;
  ruleId?: string;
  resource?: string;
  azureResourceId?: string;
  subscriptionId?: string;
  resourceGroup?: string;
  remediation?: string;
  sourceUrl?: string;
  metadata?: Record<string, unknown>;
  /** Scanner-native stable identity, preferred over positional fingerprinting. */
  stableId?: string;
}

/**
 * Assemble a normalized finding from adapter-supplied fields plus scan context,
 * computing the fingerprint and derived id.
 *
 * Centralised so no adapter can forget the fingerprint or set lifecycle fields
 * by hand.
 */
export function buildFinding(
  input: BuildFindingInput,
  context: ScanContext,
): SecurityFinding {
  const fingerprintInput: FingerprintInput = {
    scanner: context.scanner,
    stableId: input.stableId,
    ruleId: input.ruleId,
    title: input.title,
    repositoryId: context.repositoryId,
    repositoryName: context.repositoryName,
    file: input.file,
    startLine: input.startLine,
    packageName: input.packageName,
    cve: input.cve,
    resource: input.resource,
    azureResourceId: input.azureResourceId,
    environment: context.environment,
  };

  const fingerprint = generateFindingFingerprint(fingerprintInput);

  return {
    id: findingIdFromFingerprint(fingerprint),
    fingerprint,
    scanner: context.scanner,
    category: input.category,
    severity: input.severity,
    title: normalizeTitle(input.title),
    description: input.description,
    repositoryId: context.repositoryId,
    repositoryName: context.repositoryName,
    branch: context.branch,
    commitSha: context.commitSha,
    applicationId: context.applicationId,
    environment: context.environment,
    file: input.file,
    startLine: input.startLine,
    endLine: input.endLine,
    packageName: input.packageName,
    packageVersion: input.packageVersion,
    fixedVersion: input.fixedVersion,
    cve: input.cve,
    cwe: input.cwe,
    ruleId: input.ruleId,
    resource: input.resource,
    azureResourceId: input.azureResourceId,
    subscriptionId: input.subscriptionId,
    resourceGroup: input.resourceGroup,
    status: "OPEN",
    firstDetectedAt: context.scannedAt,
    lastDetectedAt: context.scannedAt,
    remediation: input.remediation,
    sourceUrl: input.sourceUrl ?? context.workflowRunUrl,
    metadata: input.metadata ? compactMetadata(input.metadata) : undefined,
  };
}
