import type { Severity } from "@/domain/security/enums";
import type { ScanContext, SecurityFinding } from "@/domain/security/finding";
import { isSarifDocument, parseSarif } from "../parsers/sarif-parser";
import { normalizeSeverity } from "../normalization/severity";
import {
  arr,
  buildFinding,
  extractCwe,
  isRecord,
  positiveInt,
  str,
  strArray,
} from "./shared";
import type { ScannerAdapter, ScanResultFormat } from "./scanner-adapter";

/**
 * Semgrep adapter.
 *
 * Semgrep emits both SARIF (`--sarif`) and a richer native JSON (`--json`).
 * The native format is preferred when available because it carries
 * `extra.metadata` — CWE, OWASP category, confidence, impact, likelihood — and
 * `extra.fingerprint`, a stable identity that survives line movement.
 *
 * Category is always SAST.
 */

/**
 * Semgrep's `severity` has three values (ERROR/WARNING/INFO), which collapses
 * everything serious into one bucket. Where the rule also declares
 * `impact: HIGH`, the finding is promoted to CRITICAL.
 *
 * This is a documented normalization policy, not a computed risk score: it maps
 * two scanner-supplied fields onto the shared scale so a Semgrep ERROR does not
 * permanently outrank a Trivy CRITICAL in the same table.
 */
function resolveSemgrepSeverity(
  severity: unknown,
  metadata: Record<string, unknown>,
): Severity {
  // A rule that declares a numeric security-severity wins outright.
  const declared = metadata["security-severity"];
  if (declared !== undefined) {
    const fromScore = normalizeSeverity(declared);
    if (fromScore !== "UNKNOWN") return fromScore;
  }

  const base = normalizeSeverity(severity);
  const impact = str(metadata.impact)?.toUpperCase();
  const confidence = str(metadata.confidence)?.toUpperCase();

  if (base === "HIGH" && impact === "HIGH" && confidence !== "LOW") {
    return "CRITICAL";
  }
  return base;
}

interface SemgrepResultShape {
  check_id?: unknown;
  path?: unknown;
  start?: unknown;
  end?: unknown;
  extra?: unknown;
}

function parseNativeResult(
  raw: unknown,
  context: ScanContext,
): SecurityFinding | undefined {
  if (!isRecord(raw)) return undefined;

  const result = raw as SemgrepResultShape;
  const checkId = str(result.check_id);
  const extra = isRecord(result.extra) ? result.extra : {};
  const metadata = isRecord(extra.metadata) ? extra.metadata : {};

  const message = str(extra.message);
  const title = message ?? checkId ?? "Semgrep finding";

  const start = isRecord(result.start) ? result.start : undefined;
  const end = isRecord(result.end) ? result.end : undefined;

  const references = strArray(metadata.references);
  const cweTokens = strArray(metadata.cwe);

  return buildFinding(
    {
      category: "SAST",
      severity: resolveSemgrepSeverity(extra.severity, metadata),
      title,
      // The full rule message is the description only when it differs from the
      // title; Semgrep usually repeats it.
      description: str(metadata.description) ?? undefined,
      file: str(result.path),
      startLine: positiveInt(start?.line),
      endLine: positiveInt(end?.line),
      cwe: extractCwe(cweTokens, checkId),
      ruleId: checkId,
      // `extra.fix` is Semgrep's own autofix suggestion — scanner-supplied
      // remediation, never synthesised here.
      remediation: str(extra.fix),
      sourceUrl: str(metadata.shortlink) ?? references[0],
      stableId: str(extra.fingerprint),
      metadata: {
        owasp: strArray(metadata.owasp),
        cweFull: cweTokens,
        confidence: str(metadata.confidence),
        impact: str(metadata.impact),
        likelihood: str(metadata.likelihood),
        technology: strArray(metadata.technology),
        subcategory: strArray(metadata.subcategory),
        references,
      },
    },
    context,
  );
}

export class SemgrepAdapter implements ScannerAdapter {
  readonly scanner = "SEMGREP" as const;
  readonly formats: readonly ScanResultFormat[] = ["sarif", "json"];

  canHandle(input: unknown): boolean {
    if (isSarifDocument(input)) {
      return this.isSemgrepSarif(input);
    }
    if (!isRecord(input)) return false;

    // Native Semgrep JSON: a `results` array whose entries carry `check_id`.
    const results = arr(input.results);
    if (results.length > 0) {
      return results.some(
        (entry) => isRecord(entry) && typeof entry.check_id === "string",
      );
    }

    // An empty clean scan still identifies itself via its envelope keys.
    return (
      Array.isArray(input.results) &&
      (isRecord(input.paths) || Array.isArray(input.errors))
    );
  }

  private isSemgrepSarif(input: unknown): boolean {
    if (!isRecord(input) || !Array.isArray(input.runs)) return false;
    return input.runs.some((run) => {
      if (!isRecord(run)) return false;
      const tool = isRecord(run.tool) ? run.tool : undefined;
      const driver = isRecord(tool?.driver) ? tool.driver : undefined;
      return /semgrep/i.test(str(driver?.name) ?? "");
    });
  }

  async parse(
    input: unknown,
    context: ScanContext,
  ): Promise<SecurityFinding[]> {
    if (isSarifDocument(input)) {
      return parseSarif(input, context, {
        category: "SAST",
        refine: (finding, result) => ({
          ...finding,
          // Semgrep SARIF puts the rule id in `ruleId`; when the message
          // already begins with it, keep the table cell clean.
          cwe:
            finding.cwe ??
            extractCwe(result.rule?.tags, result.rule?.shortDescription),
        }),
      });
    }

    if (!isRecord(input)) return [];

    return arr(input.results)
      .map((raw) => parseNativeResult(raw, context))
      .filter((finding): finding is SecurityFinding => finding !== undefined);
  }
}
