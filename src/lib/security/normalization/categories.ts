import type { FindingCategory, ScannerType } from "@/domain/security/enums";

/**
 * Category normalization.
 *
 * Categories answer "what kind of problem is this", which is orthogonal to
 * "which tool found it". A React component must never work this out — it asks
 * for `finding.category` and renders it.
 *
 * Most scanners are single-purpose and get a fixed category. Trivy is not: one
 * Trivy report can carry OS package CVEs, language dependency CVEs, IaC
 * misconfigurations and secrets side by side, so it resolves per result.
 */

/** The category a scanner produces when nothing more specific is known. */
const SCANNER_DEFAULT_CATEGORY: Record<ScannerType, FindingCategory> = {
  SEMGREP: "SAST",
  TRIVY: "SCA",
  CHECKOV: "IAC",
  GITLEAKS: "SECRET",
  UNKNOWN: "OTHER",
};

export function defaultCategoryForScanner(
  scanner: ScannerType,
): FindingCategory {
  return SCANNER_DEFAULT_CATEGORY[scanner] ?? "OTHER";
}

/**
 * Trivy result classes (`Results[].Class`).
 *
 * - `os-pkgs`   packages from the base image  -> CONTAINER
 * - `lang-pkgs` application dependencies      -> SCA
 * - `config`    Terraform/K8s/Dockerfile      -> IAC
 * - `secret`    embedded credentials          -> SECRET
 * - `license`   license compliance            -> CONFIGURATION
 */
const TRIVY_CLASS_CATEGORY: Record<string, FindingCategory> = {
  "os-pkgs": "CONTAINER",
  "lang-pkgs": "SCA",
  config: "IAC",
  secret: "SECRET",
  license: "CONFIGURATION",
};

export function categoryFromTrivyClass(
  resultClass: unknown,
  fallback: FindingCategory = "SCA",
): FindingCategory {
  if (typeof resultClass !== "string") return fallback;
  return TRIVY_CLASS_CATEGORY[resultClass.trim().toLowerCase()] ?? fallback;
}

/**
 * Trivy misconfiguration targets are typed by `Type` (`terraform`,
 * `dockerfile`, `kubernetes`, `cloudformation`, `azure-arm`, ...). A
 * Dockerfile misconfiguration is a container concern; the rest are IaC.
 */
export function categoryFromTrivyMisconfigType(
  type: unknown,
): FindingCategory {
  if (typeof type !== "string") return "IAC";
  const normalized = type.trim().toLowerCase();
  if (normalized === "dockerfile" || normalized === "docker") return "CONTAINER";
  return "IAC";
}

/**
 * Best-effort category from a free-form tag list, used when reading generic
 * SARIF where the producing tool is unknown. Order matters: the first tag that
 * maps wins, so a result tagged both `security` and `secret` is a SECRET.
 */
const TAG_CATEGORY: Array<[RegExp, FindingCategory]> = [
  [/secret|credential|password|token|api[-_ ]?key/i, "SECRET"],
  [/iac|terraform|cloudformation|kubernetes|k8s|arm[-_ ]?template/i, "IAC"],
  [/container|docker|image/i, "CONTAINER"],
  [/dependenc|supply[-_ ]?chain|sca|package|library/i, "SCA"],
  [/dast|zap|dynamic/i, "DAST"],
  [/misconfig|configuration|hardening|compliance/i, "CONFIGURATION"],
  [/sast|injection|xss|static[-_ ]?analysis|cwe/i, "SAST"],
];

export function categoryFromTags(
  tags: readonly unknown[] | undefined,
  fallback: FindingCategory = "OTHER",
): FindingCategory {
  if (!tags?.length) return fallback;
  const joined = tags.filter((tag) => typeof tag === "string").join(" ");
  if (!joined) return fallback;

  for (const [pattern, category] of TAG_CATEGORY) {
    if (pattern.test(joined)) return category;
  }
  return fallback;
}

export function isVulnerabilityCategory(category: FindingCategory): boolean {
  return category === "SCA" || category === "CONTAINER";
}
