import type { Severity } from "@/domain/security/enums";
import type { ScanContext, SecurityFinding } from "@/domain/security/finding";
import { isSarifDocument, parseSarif } from "../parsers/sarif-parser";
import {
  arr,
  buildFinding,
  isRecord,
  positiveInt,
  str,
  strArray,
} from "./shared";
import type { ScannerAdapter, ScanResultFormat } from "./scanner-adapter";

/**
 * Gitleaks adapter.
 *
 * SECURITY-CRITICAL: Gitleaks output contains the secret it found, verbatim, in
 * `Secret`, `Match` and the surrounding code context. Ingesting those fields
 * would turn the dashboard database — and every API response and log line
 * derived from it — into a secondary credential store.
 *
 * This adapter therefore never copies `Secret` or `Match` into a finding. It
 * keeps only non-reversible evidence: the rule that fired, the file, the line,
 * the commit, and the entropy score. `redactMatch` records the shape of the
 * secret (length and a masked prefix) so a human can recognise it in the source
 * without the value being recoverable from the dashboard.
 */

/**
 * Gitleaks has no severity concept: every result is "a secret was committed".
 * Treating a live credential in version control as CRITICAL is a policy
 * decision, stated here in one place rather than scattered through the UI.
 * Change this constant to change the policy.
 */
export const GITLEAKS_DEFAULT_SEVERITY: Severity = "CRITICAL";

/** Fields that must never reach the domain model. */
const FORBIDDEN_FIELDS = ["Secret", "Match", "Code", "secret", "match"] as const;

/**
 * Reduce a raw match to a non-reversible descriptor: first two characters plus
 * length. Enough to correlate with the source line, useless as a credential.
 */
export function redactMatch(value: unknown): string | undefined {
  const text = str(value);
  if (!text) return undefined;
  const prefix = text.slice(0, 2).replace(/[^\w-]/g, "");
  return `${prefix}${"*".repeat(Math.min(8, Math.max(1, text.length - 2)))} (${text.length} chars)`;
}

function parseNativeResult(
  raw: unknown,
  context: ScanContext,
): SecurityFinding | undefined {
  if (!isRecord(raw)) return undefined;

  const ruleId = str(raw.RuleID) ?? str(raw.ruleID) ?? str(raw.rule);
  const description = str(raw.Description) ?? str(raw.description);
  const file = str(raw.File) ?? str(raw.file);

  if (!ruleId && !description && !file) return undefined;

  const title = description ?? (ruleId ? `Secret detected: ${ruleId}` : "Secret detected");
  const startLine = positiveInt(raw.StartLine ?? raw.startLine);
  const commit = str(raw.Commit) ?? str(raw.commit);

  return buildFinding(
    {
      category: "SECRET",
      severity: GITLEAKS_DEFAULT_SEVERITY,
      title,
      description: undefined,
      file,
      startLine,
      endLine: positiveInt(raw.EndLine ?? raw.endLine),
      ruleId,
      // Gitleaks ships a stable per-finding fingerprint of the form
      // `commit:file:rule:line`; prefer it over our positional identity.
      stableId: str(raw.Fingerprint) ?? str(raw.fingerprint),
      metadata: {
        entropy:
          typeof raw.Entropy === "number" ? raw.Entropy : undefined,
        commit,
        tags: strArray(raw.Tags),
        // Redacted shape only — never the secret itself.
        matchPreview: redactMatch(raw.Match),
        redacted: true,
      },
    },
    context,
  );
}

export class GitleaksAdapter implements ScannerAdapter {
  readonly scanner = "GITLEAKS" as const;
  readonly formats: readonly ScanResultFormat[] = ["sarif", "json"];

  canHandle(input: unknown): boolean {
    if (isSarifDocument(input)) {
      if (!isRecord(input) || !Array.isArray(input.runs)) return false;
      return input.runs.some((run) => {
        if (!isRecord(run)) return false;
        const tool = isRecord(run.tool) ? run.tool : undefined;
        const driver = isRecord(tool?.driver) ? tool.driver : undefined;
        return /gitleaks/i.test(str(driver?.name) ?? "");
      });
    }

    // Native Gitleaks JSON is a bare array of leak objects.
    if (!Array.isArray(input)) return false;
    if (input.length === 0) return false;
    return input.some(
      (entry) =>
        isRecord(entry) &&
        (typeof entry.RuleID === "string" || typeof entry.ruleID === "string") &&
        ("File" in entry || "Commit" in entry || "StartLine" in entry),
    );
  }

  async parse(
    input: unknown,
    context: ScanContext,
  ): Promise<SecurityFinding[]> {
    if (isSarifDocument(input)) {
      return parseSarif(input, context, {
        category: "SECRET",
        defaultSeverity: GITLEAKS_DEFAULT_SEVERITY,
        refine: (finding, result) => ({
          ...finding,
          severity: GITLEAKS_DEFAULT_SEVERITY,
          // Gitleaks SARIF puts the matched line — secret included — in
          // `message.text`, which the generic parser uses as the title. Rebuild
          // the title from rule metadata so the secret cannot reach the model
          // through it, and drop the description for the same reason.
          title:
            result.rule?.shortDescription ??
            result.rule?.name ??
            (result.ruleId
              ? `Secret detected: ${result.ruleId}`
              : "Secret detected"),
          description: undefined,
          metadata: { ...finding.metadata, redacted: true },
        }),
      });
    }

    return arr(input)
      .map((raw) => parseNativeResult(raw, context))
      .filter((finding): finding is SecurityFinding => finding !== undefined);
  }
}

/**
 * Test seam: asserts no forbidden field survived into a finding.
 * Used by the adapter tests to prove redaction rather than assume it.
 */
export function containsRawSecretFields(finding: SecurityFinding): boolean {
  const serialized = JSON.stringify(finding);
  return FORBIDDEN_FIELDS.some((field) =>
    new RegExp(`"${field}"\\s*:`).test(serialized),
  );
}
