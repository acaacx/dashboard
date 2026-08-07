import type { FindingCategory, ScannerType } from "@/domain/security/enums";
import { InvalidSarifError } from "@/domain/security/errors";
import type { ScanContext, SecurityFinding } from "@/domain/security/finding";
import { categoryFromTags } from "../normalization/categories";
import {
  findingIdFromFingerprint,
  generateFindingFingerprint,
} from "../normalization/fingerprint";
import { normalizeSecuritySeverity } from "../normalization/severity";
import { recordSecurityEvent } from "../observability";

/**
 * SARIF 2.1.0 reader.
 *
 * This module knows SARIF and nothing else. It has no idea which tool produced
 * the document, and it must stay that way: scanner-specific behaviour belongs
 * in the adapter, which calls in here for the generic 90% and then overrides
 * what it alone knows.
 *
 * The parser is defensive rather than strict. A real SARIF file from a real
 * scanner routinely omits optional fields, nests rules in extensions, or
 * carries vendor properties in a shape the spec never anticipated. A missing
 * optional field yields an incomplete finding, not an exception. Only a
 * document that is not recognisably SARIF is rejected.
 */

/** Guard against a hostile or runaway document exhausting memory. */
export const MAX_SARIF_RESULTS = 50_000;

const CVE_PATTERN = /\bCVE-\d{4}-\d{4,7}\b/i;
const CWE_PATTERN = /\bCWE-\d+\b/i;

export interface SarifRuleView {
  id?: string;
  name?: string;
  shortDescription?: string;
  fullDescription?: string;
  help?: string;
  helpUri?: string;
  level?: unknown;
  securitySeverity?: unknown;
  tags: string[];
  properties: Record<string, unknown>;
}

export interface SarifLocationView {
  file?: string;
  startLine?: number;
  endLine?: number;
}

export interface SarifResultView {
  ruleId?: string;
  level?: unknown;
  kind?: string;
  message?: string;
  locations: SarifLocationView[];
  properties: Record<string, unknown>;
  partialFingerprints: Record<string, string>;
  suppressed: boolean;
  rule?: SarifRuleView;
}

export interface SarifRunView {
  toolName?: string;
  toolVersion?: string;
  informationUri?: string;
  results: SarifResultView[];
}

export interface SarifDocumentView {
  version?: string;
  runs: SarifRunView[];
}

// --- structural helpers -----------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== ""
    ? value.trim()
    : undefined;
}

function asPositiveInt(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value > 0
    ? value
    : undefined;
}

/** SARIF multiformatMessageString: `{ text, markdown }`. */
function messageText(value: unknown): string | undefined {
  if (!isRecord(value)) return undefined;
  return asString(value.text) ?? asString(value.markdown);
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === "string");
}

/**
 * Detect whether a payload is plausibly a SARIF document, without throwing.
 * Adapters use this in `canHandle` to route between SARIF and native JSON.
 */
export function isSarifDocument(input: unknown): boolean {
  if (!isRecord(input)) return false;
  if (!Array.isArray(input.runs)) return false;
  // `version` is required by the spec but some producers omit it; the presence
  // of a runs array containing tool descriptors is the reliable signal.
  return (
    typeof input.version === "string" ||
    typeof input.$schema === "string" ||
    input.runs.some((run) => isRecord(run) && isRecord(run.tool))
  );
}

// --- parsing ----------------------------------------------------------------

function parseRule(raw: unknown): SarifRuleView | undefined {
  if (!isRecord(raw)) return undefined;

  const properties = isRecord(raw.properties) ? raw.properties : {};
  const defaultConfiguration = isRecord(raw.defaultConfiguration)
    ? raw.defaultConfiguration
    : undefined;

  return {
    id: asString(raw.id),
    name: asString(raw.name),
    shortDescription: messageText(raw.shortDescription),
    fullDescription: messageText(raw.fullDescription),
    help: messageText(raw.help),
    helpUri: asString(raw.helpUri),
    level: defaultConfiguration?.level,
    securitySeverity: properties["security-severity"],
    tags: stringArray(properties.tags),
    properties,
  };
}

function parseLocations(raw: unknown): SarifLocationView[] {
  if (!Array.isArray(raw)) return [];

  const locations: SarifLocationView[] = [];
  for (const entry of raw) {
    if (!isRecord(entry)) continue;
    const physical = isRecord(entry.physicalLocation)
      ? entry.physicalLocation
      : undefined;
    if (!physical) continue;

    const artifact = isRecord(physical.artifactLocation)
      ? physical.artifactLocation
      : undefined;
    const region = isRecord(physical.region) ? physical.region : undefined;

    locations.push({
      file: asString(artifact?.uri),
      startLine: asPositiveInt(region?.startLine),
      endLine: asPositiveInt(region?.endLine),
    });
  }
  return locations;
}

function parsePartialFingerprints(raw: unknown): Record<string, string> {
  if (!isRecord(raw)) return {};
  const output: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value === "string") output[key] = value;
  }
  return output;
}

/**
 * Parse and structurally validate a SARIF document.
 * @throws InvalidSarifError when the payload is not a SARIF document at all.
 */
export function parseSarifDocument(input: unknown): SarifDocumentView {
  if (!isRecord(input)) {
    throw new InvalidSarifError("expected an object at the document root");
  }
  if (!Array.isArray(input.runs)) {
    throw new InvalidSarifError("missing required property `runs`", {
      path: "runs",
    });
  }

  const version = asString(input.version);
  if (version && !version.startsWith("2.1")) {
    throw new InvalidSarifError(
      `unsupported version "${version}"; only SARIF 2.1.0 is supported`,
      { path: "version" },
    );
  }

  let remaining = MAX_SARIF_RESULTS;
  let truncated = false;

  const runs: SarifRunView[] = input.runs.map((rawRun, runIndex) => {
    if (!isRecord(rawRun)) {
      throw new InvalidSarifError("run entry is not an object", {
        path: `runs[${runIndex}]`,
      });
    }

    const tool = isRecord(rawRun.tool) ? rawRun.tool : undefined;
    const driver = isRecord(tool?.driver) ? tool.driver : undefined;

    // Rules can live on the driver or on any extension (Semgrep uses the
    // driver; some GitHub-produced documents use extensions).
    const ruleSources: unknown[] = [];
    if (Array.isArray(driver?.rules)) ruleSources.push(...driver.rules);
    if (Array.isArray(tool?.extensions)) {
      for (const extension of tool.extensions) {
        if (isRecord(extension) && Array.isArray(extension.rules)) {
          ruleSources.push(...extension.rules);
        }
      }
    }

    const rules = ruleSources
      .map(parseRule)
      .filter((rule): rule is SarifRuleView => rule !== undefined);

    const rulesById = new Map<string, SarifRuleView>();
    rules.forEach((rule) => {
      if (rule.id) rulesById.set(rule.id, rule);
    });

    const rawResults = Array.isArray(rawRun.results) ? rawRun.results : [];
    const results: SarifResultView[] = [];

    for (const rawResult of rawResults) {
      if (!isRecord(rawResult)) continue;
      if (remaining <= 0) {
        truncated = true;
        break;
      }
      remaining -= 1;

      const ruleId = asString(rawResult.ruleId);
      const ruleIndex =
        typeof rawResult.ruleIndex === "number"
          ? rawResult.ruleIndex
          : isRecord(rawResult.rule) && typeof rawResult.rule.index === "number"
            ? rawResult.rule.index
            : undefined;

      const rule =
        (ruleId ? rulesById.get(ruleId) : undefined) ??
        (ruleIndex !== undefined ? rules[ruleIndex] : undefined);

      results.push({
        ruleId: ruleId ?? rule?.id,
        level: rawResult.level,
        kind: asString(rawResult.kind),
        message: messageText(rawResult.message),
        locations: parseLocations(rawResult.locations),
        properties: isRecord(rawResult.properties) ? rawResult.properties : {},
        partialFingerprints: parsePartialFingerprints(
          rawResult.partialFingerprints,
        ),
        suppressed:
          Array.isArray(rawResult.suppressions) &&
          rawResult.suppressions.length > 0,
        rule,
      });
    }

    return {
      toolName: asString(driver?.name),
      toolVersion: asString(driver?.version) ?? asString(driver?.semanticVersion),
      informationUri: asString(driver?.informationUri),
      results,
    };
  });

  if (truncated) {
    recordSecurityEvent("scan.parser.error", {
      reason: "sarif_results_truncated",
      limit: MAX_SARIF_RESULTS,
    });
  }

  return { version, runs };
}

/** Tool driver name of the first run, used for scanner detection. */
export function sarifToolName(input: unknown): string | undefined {
  if (!isRecord(input) || !Array.isArray(input.runs)) return undefined;
  for (const run of input.runs) {
    if (!isRecord(run)) continue;
    const tool = isRecord(run.tool) ? run.tool : undefined;
    const driver = isRecord(tool?.driver) ? tool.driver : undefined;
    const name = asString(driver?.name);
    if (name) return name;
  }
  return undefined;
}

const TOOL_NAME_SCANNER: Array<[RegExp, ScannerType]> = [
  [/semgrep/i, "SEMGREP"],
  [/trivy/i, "TRIVY"],
  [/checkov|bridgecrew|prisma/i, "CHECKOV"],
  [/gitleaks/i, "GITLEAKS"],
];

/** Best-effort scanner identification from the SARIF tool driver name. */
export function detectScannerFromSarif(input: unknown): ScannerType {
  const name = sarifToolName(input);
  if (!name) return "UNKNOWN";
  for (const [pattern, scanner] of TOOL_NAME_SCANNER) {
    if (pattern.test(name)) return scanner;
  }
  return "UNKNOWN";
}

// --- normalization ----------------------------------------------------------

function extractPattern(
  pattern: RegExp,
  ...candidates: Array<string | undefined>
): string | undefined {
  for (const candidate of candidates) {
    if (!candidate) continue;
    const match = pattern.exec(candidate);
    if (match) return match[0].toUpperCase();
  }
  return undefined;
}

/**
 * Prefer a scanner-supplied stable identifier over positional identity.
 * SARIF `partialFingerprints` is exactly this: values a tool guarantees are
 * stable across runs even when line numbers move.
 */
function stableIdFromResult(result: SarifResultView): string | undefined {
  const preferredKeys = [
    "primaryLocationLineHash",
    "commitSha/v1",
    "fingerprint",
  ];
  for (const key of preferredKeys) {
    const value = result.partialFingerprints[key];
    if (value) return `${key}:${value}`;
  }
  const [firstKey, firstValue] = Object.entries(result.partialFingerprints)[0] ?? [];
  return firstKey && firstValue ? `${firstKey}:${firstValue}` : undefined;
}

export interface SarifNormalizationOptions {
  /** Force a category for every result (single-purpose tools). */
  category?: FindingCategory;
  /** Resolve a category per result (multi-purpose tools such as Trivy). */
  resolveCategory?: (result: SarifResultView) => FindingCategory;
  /** Applied when neither the result nor the rule carries usable severity. */
  defaultSeverity?: ReturnType<typeof normalizeSecuritySeverity>;
  /** Last chance to adjust a finding with knowledge only the adapter has. */
  refine?: (
    finding: SecurityFinding,
    result: SarifResultView,
  ) => SecurityFinding;
}

/**
 * Convert one parsed SARIF result into a normalized finding.
 * Exported so adapters can reuse it for a subset of results.
 */
export function sarifResultToFinding(
  result: SarifResultView,
  context: ScanContext,
  options: SarifNormalizationOptions = {},
): SecurityFinding {
  const rule = result.rule;

  const title =
    result.message ??
    rule?.shortDescription ??
    rule?.name ??
    result.ruleId ??
    "Untitled finding";

  const description =
    rule?.fullDescription ??
    (result.message && result.message !== title ? result.message : undefined);

  let severity = normalizeSecuritySeverity(
    result.properties["security-severity"] ?? rule?.securitySeverity,
    result.level ?? rule?.level,
  );
  if (severity === "UNKNOWN" && options.defaultSeverity) {
    severity = options.defaultSeverity;
  }

  const category =
    options.resolveCategory?.(result) ??
    options.category ??
    categoryFromTags(rule?.tags);

  const location = result.locations[0];

  const cve = extractPattern(
    CVE_PATTERN,
    result.ruleId,
    title,
    rule?.shortDescription,
    ...(rule?.tags ?? []),
  );
  const cwe = extractPattern(
    CWE_PATTERN,
    ...(rule?.tags ?? []),
    result.ruleId,
    rule?.shortDescription,
  );

  const fingerprint = generateFindingFingerprint({
    scanner: context.scanner,
    stableId: stableIdFromResult(result),
    ruleId: result.ruleId,
    title,
    repositoryId: context.repositoryId,
    repositoryName: context.repositoryName,
    file: location?.file,
    startLine: location?.startLine,
    cve,
    environment: context.environment,
  });

  const finding: SecurityFinding = {
    id: findingIdFromFingerprint(fingerprint),
    fingerprint,
    scanner: context.scanner,
    category,
    severity,
    title: title.split("\n")[0].slice(0, 300),
    description,
    repositoryId: context.repositoryId,
    repositoryName: context.repositoryName,
    branch: context.branch,
    commitSha: context.commitSha,
    applicationId: context.applicationId,
    environment: context.environment,
    file: location?.file,
    startLine: location?.startLine,
    endLine: location?.endLine,
    cve,
    cwe,
    ruleId: result.ruleId,
    status: result.suppressed ? "SUPPRESSED" : "OPEN",
    firstDetectedAt: context.scannedAt,
    lastDetectedAt: context.scannedAt,
    // Only ever the scanner's own words. Never generated here.
    remediation: rule?.help,
    sourceUrl: rule?.helpUri ?? context.workflowRunUrl,
    metadata: {
      sarifKind: result.kind,
      tags: rule?.tags?.length ? rule.tags : undefined,
    },
  };

  return options.refine ? options.refine(finding, result) : finding;
}

/**
 * Convert a whole SARIF document into normalized findings.
 *
 * Results with `kind` of `pass` or `notApplicable` are dropped: they record
 * that a rule was evaluated and did not fire, which is scan metadata rather
 * than a finding.
 */
export function parseSarif(
  input: unknown,
  context: ScanContext,
  options: SarifNormalizationOptions = {},
): SecurityFinding[] {
  const document = parseSarifDocument(input);

  const findings: SecurityFinding[] = [];
  for (const run of document.runs) {
    for (const result of run.results) {
      if (result.kind === "pass" || result.kind === "notApplicable") continue;
      findings.push(sarifResultToFinding(result, context, options));
    }
  }
  return findings;
}
