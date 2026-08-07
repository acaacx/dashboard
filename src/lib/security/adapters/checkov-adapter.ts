import type { Severity } from "@/domain/security/enums";
import type { ScanContext, SecurityFinding } from "@/domain/security/finding";
import { normalizeSeverity } from "../normalization/severity";
import { isSarifDocument, parseSarif } from "../parsers/sarif-parser";
import {
  arr,
  buildFinding,
  isRecord,
  positiveInt,
  str,
} from "./shared";
import type { ScannerAdapter, ScanResultFormat } from "./scanner-adapter";

/**
 * Checkov adapter.
 *
 * Checkov reports IaC policy violations for Terraform, CloudFormation, ARM,
 * Kubernetes, Helm and Dockerfiles. Category is always IAC.
 *
 * Two envelope shapes exist in the wild and both are handled:
 *  - a single object `{ check_type, results: { failed_checks: [...] }, summary }`
 *  - an array of those objects, emitted when one run covers several frameworks
 */

/**
 * Open-source Checkov emits `severity: null` — severity is a Prisma Cloud
 * feature. Without a default, every IaC finding would render as UNKNOWN and
 * sort to the bottom of the table, which is worse than a stated assumption.
 *
 * MEDIUM is the floor, not a judgement about any specific policy: a Checkov
 * result that ships a real severity (Prisma-linked runs, `bc_check_id`) always
 * overrides it.
 */
export const CHECKOV_DEFAULT_SEVERITY: Severity = "MEDIUM";

function parseFailedCheck(
  raw: unknown,
  checkType: string | undefined,
  context: ScanContext,
): SecurityFinding | undefined {
  if (!isRecord(raw)) return undefined;

  const checkId = str(raw.check_id);
  const checkName = str(raw.check_name);
  if (!checkId && !checkName) return undefined;

  const lineRange = arr(raw.file_line_range);
  const startLine = positiveInt(lineRange[0]);
  const endLine = positiveInt(lineRange[1]);

  const severity = normalizeSeverity(raw.severity);

  return buildFinding(
    {
      category: "IAC",
      severity: severity === "UNKNOWN" ? CHECKOV_DEFAULT_SEVERITY : severity,
      title: checkName ?? checkId ?? "Policy violation",
      description: str(raw.description),
      file: str(raw.file_path) ?? str(raw.repo_file_path),
      startLine,
      endLine,
      ruleId: checkId ?? str(raw.bc_check_id),
      // e.g. `azurerm_storage_account.public` — the thing to actually fix.
      resource: str(raw.resource) ?? str(raw.resource_address),
      // `guideline` is a link to Checkov's own remediation documentation.
      sourceUrl: str(raw.guideline),
      metadata: {
        checkType,
        bcCheckId: str(raw.bc_check_id),
        checkClass: str(raw.check_class),
        resourceType: str(raw.resource_type),
        // `code_block` is the offending IaC source. It is intentionally not
        // stored: it is untrusted text, it bloats every API response, and the
        // file + line reference already points at it.
        codeBlockOmitted: true,
      },
    },
    context,
  );
}

/** Normalize both envelope shapes into a flat list of report objects. */
function reportObjects(input: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(input)) {
    return input.filter(isRecord);
  }
  return isRecord(input) ? [input] : [];
}

export class CheckovAdapter implements ScannerAdapter {
  readonly scanner = "CHECKOV" as const;
  readonly formats: readonly ScanResultFormat[] = ["sarif", "json"];

  canHandle(input: unknown): boolean {
    if (isSarifDocument(input)) {
      if (!isRecord(input) || !Array.isArray(input.runs)) return false;
      return input.runs.some((run) => {
        if (!isRecord(run)) return false;
        const tool = isRecord(run.tool) ? run.tool : undefined;
        const driver = isRecord(tool?.driver) ? tool.driver : undefined;
        return /checkov|bridgecrew|prisma/i.test(str(driver?.name) ?? "");
      });
    }

    const reports = reportObjects(input);
    if (reports.length === 0) return false;

    return reports.some((report) => {
      if (typeof report.check_type === "string") return true;
      const results = isRecord(report.results) ? report.results : undefined;
      return (
        Array.isArray(results?.failed_checks) ||
        Array.isArray(results?.passed_checks)
      );
    });
  }

  async parse(
    input: unknown,
    context: ScanContext,
  ): Promise<SecurityFinding[]> {
    if (isSarifDocument(input)) {
      return parseSarif(input, context, {
        category: "IAC",
        defaultSeverity: CHECKOV_DEFAULT_SEVERITY,
      });
    }

    const findings: SecurityFinding[] = [];

    for (const report of reportObjects(input)) {
      const checkType = str(report.check_type);
      const results = isRecord(report.results) ? report.results : undefined;
      if (!results) continue;

      // Only failed checks become findings. `passed_checks` is compliance
      // evidence, not a finding, and ingesting it would swamp the table.
      for (const raw of arr(results.failed_checks)) {
        const finding = parseFailedCheck(raw, checkType, context);
        if (finding) findings.push(finding);
      }
    }

    return findings;
  }
}
