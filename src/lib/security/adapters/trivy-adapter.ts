import type { FindingCategory } from "@/domain/security/enums";
import type { ScanContext, SecurityFinding } from "@/domain/security/finding";
import {
  categoryFromTrivyClass,
  categoryFromTrivyMisconfigType,
} from "../normalization/categories";
import { normalizeSeverity } from "../normalization/severity";
import { isSarifDocument, parseSarif } from "../parsers/sarif-parser";
import {
  arr,
  buildFinding,
  extractCve,
  extractCwe,
  isRecord,
  positiveInt,
  str,
  strArray,
} from "./shared";
import type { ScannerAdapter, ScanResultFormat } from "./scanner-adapter";

/**
 * Trivy adapter.
 *
 * Trivy is the multi-purpose scanner of the set: a single report can contain OS
 * package CVEs, language dependency CVEs, IaC misconfigurations, secrets and
 * license issues, each under a different `Results[].Class`. Category is
 * therefore resolved per result, never per scanner.
 *
 * Native JSON is strongly preferred over SARIF here: Trivy's SARIF loses
 * `PkgName`, `InstalledVersion` and `FixedVersion`, which are exactly the
 * fields that make a dependency finding actionable.
 */

function trivySecrets(
  entries: unknown,
  target: string | undefined,
  category: FindingCategory,
  context: ScanContext,
): SecurityFinding[] {
  return arr(entries).flatMap((raw) => {
    if (!isRecord(raw)) return [];
    const ruleId = str(raw.RuleID);
    const title = str(raw.Title) ?? ruleId ?? "Secret detected";

    return [
      buildFinding(
        {
          category,
          severity: normalizeSeverity(raw.Severity),
          title,
          file: target,
          startLine: positiveInt(raw.StartLine),
          endLine: positiveInt(raw.EndLine),
          ruleId,
          metadata: {
            secretCategory: str(raw.Category),
            // `Match` holds the secret itself — deliberately not stored.
            redacted: true,
          },
        },
        context,
      ),
    ];
  });
}

function trivyVulnerabilities(
  entries: unknown,
  target: string | undefined,
  category: FindingCategory,
  artifactName: string | undefined,
  context: ScanContext,
): SecurityFinding[] {
  return arr(entries).flatMap((raw) => {
    if (!isRecord(raw)) return [];

    const vulnerabilityId = str(raw.VulnerabilityID);
    const packageName = str(raw.PkgName);
    const title =
      str(raw.Title) ??
      (vulnerabilityId && packageName
        ? `${vulnerabilityId} in ${packageName}`
        : (vulnerabilityId ?? packageName ?? "Vulnerability"));

    const cvss = isRecord(raw.CVSS) ? raw.CVSS : undefined;
    const nvdScore =
      cvss && isRecord(cvss.nvd) ? cvss.nvd.V3Score ?? cvss.nvd.V2Score : undefined;

    return [
      buildFinding(
        {
          category,
          // Trivy's own vendor severity is authoritative; the NVD CVSS score is
          // the fallback when the vendor has not rated it.
          severity:
            normalizeSeverity(raw.Severity) !== "UNKNOWN"
              ? normalizeSeverity(raw.Severity)
              : normalizeSeverity(nvdScore),
          title,
          description: str(raw.Description),
          file: str(raw.PkgPath) ?? target,
          packageName,
          packageVersion: str(raw.InstalledVersion),
          fixedVersion: str(raw.FixedVersion),
          cve: extractCve(vulnerabilityId, raw.VulnerabilityID) ?? vulnerabilityId,
          cwe: extractCwe(raw.CweIDs),
          ruleId: vulnerabilityId,
          // For container scans the artifact is the image, which is the thing an
          // operator actually acts on.
          resource: artifactName,
          sourceUrl: str(raw.PrimaryURL),
          metadata: {
            status: str(raw.Status),
            publishedDate: str(raw.PublishedDate),
            lastModifiedDate: str(raw.LastModifiedDate),
            references: strArray(raw.References).slice(0, 5),
            dataSource: isRecord(raw.DataSource)
              ? str(raw.DataSource.Name)
              : undefined,
          },
        },
        context,
      ),
    ];
  });
}

function trivyMisconfigurations(
  entries: unknown,
  target: string | undefined,
  resultType: string | undefined,
  context: ScanContext,
): SecurityFinding[] {
  return arr(entries).flatMap((raw) => {
    if (!isRecord(raw)) return [];

    const id = str(raw.ID);
    const title = str(raw.Title) ?? id ?? "Misconfiguration";
    const cause = isRecord(raw.CauseMetadata) ? raw.CauseMetadata : undefined;

    return [
      buildFinding(
        {
          category: categoryFromTrivyMisconfigType(resultType),
          severity: normalizeSeverity(raw.Severity),
          title,
          description: str(raw.Description) ?? str(raw.Message),
          file: target,
          startLine: positiveInt(cause?.StartLine),
          endLine: positiveInt(cause?.EndLine),
          ruleId: id ?? str(raw.AVDID),
          resource: str(cause?.Resource),
          // `Resolution` is Trivy's own remediation text.
          remediation: str(raw.Resolution),
          sourceUrl: str(raw.PrimaryURL),
          metadata: {
            avdId: str(raw.AVDID),
            type: str(raw.Type),
            provider: str(cause?.Provider),
            service: str(cause?.Service),
            references: strArray(raw.References).slice(0, 5),
          },
        },
        context,
      ),
    ];
  });
}

export class TrivyAdapter implements ScannerAdapter {
  readonly scanner = "TRIVY" as const;
  readonly formats: readonly ScanResultFormat[] = ["sarif", "json"];

  canHandle(input: unknown): boolean {
    if (isSarifDocument(input)) {
      if (!isRecord(input) || !Array.isArray(input.runs)) return false;
      return input.runs.some((run) => {
        if (!isRecord(run)) return false;
        const tool = isRecord(run.tool) ? run.tool : undefined;
        const driver = isRecord(tool?.driver) ? tool.driver : undefined;
        return /trivy/i.test(str(driver?.name) ?? "");
      });
    }

    if (!isRecord(input)) return false;
    // Trivy's envelope: SchemaVersion + Results, or the ArtifactName/Type pair.
    const hasResults = Array.isArray(input.Results);
    return (
      hasResults &&
      ("SchemaVersion" in input ||
        "ArtifactName" in input ||
        "ArtifactType" in input)
    );
  }

  async parse(
    input: unknown,
    context: ScanContext,
  ): Promise<SecurityFinding[]> {
    if (isSarifDocument(input)) {
      // Trivy SARIF tags results with the class in rule tags; fall back to SCA.
      return parseSarif(input, context, {
        resolveCategory: (result) => {
          const tags = result.rule?.tags ?? [];
          if (tags.some((tag) => /secret/i.test(tag))) return "SECRET";
          if (tags.some((tag) => /misconfig|config/i.test(tag))) return "IAC";
          if (tags.some((tag) => /os-pkgs|container|image/i.test(tag))) {
            return "CONTAINER";
          }
          return "SCA";
        },
        refine: (finding, result) => {
          if (finding.category !== "SECRET") {
            return { ...finding, cve: finding.cve ?? extractCve(result.ruleId) };
          }
          // Same hazard as Gitleaks: a secret result's SARIF message can quote
          // the matched credential, so the title is rebuilt from rule metadata
          // and the description dropped.
          return {
            ...finding,
            title:
              result.rule?.shortDescription ??
              result.rule?.name ??
              (result.ruleId
                ? `Secret detected: ${result.ruleId}`
                : "Secret detected"),
            description: undefined,
            metadata: { ...finding.metadata, redacted: true },
          };
        },
      });
    }

    if (!isRecord(input)) return [];

    const artifactName = str(input.ArtifactName);
    const findings: SecurityFinding[] = [];

    for (const rawResult of arr(input.Results)) {
      if (!isRecord(rawResult)) continue;

      const target = str(rawResult.Target);
      const resultType = str(rawResult.Type);
      const category = categoryFromTrivyClass(rawResult.Class);

      findings.push(
        ...trivyVulnerabilities(
          rawResult.Vulnerabilities,
          target,
          category,
          artifactName,
          context,
        ),
        ...trivyMisconfigurations(
          rawResult.Misconfigurations,
          target,
          resultType,
          context,
        ),
        ...trivySecrets(rawResult.Secrets, target, "SECRET", context),
      );
    }

    return findings;
  }
}
