import { z } from "zod";

import {
  FINDING_CATEGORIES,
  FINDING_STATUSES,
  SCANNER_TYPES,
  SEVERITIES,
} from "@/domain/security/enums";
import { SCAN_RUN_STATUSES } from "@/domain/security/scan-run";

/**
 * Schema validation for everything that crosses the HTTP boundary.
 *
 * Two jobs: reject malformed input with a useful message, and bound the input
 * so a hostile or broken CI job cannot exhaust the process. Scanner payloads
 * themselves are NOT schema-validated here — they are passed to the adapters as
 * `unknown` and parsed defensively, because every scanner adds fields between
 * releases and a strict schema would reject valid reports.
 */

/** Maximum accepted scan body. Large enough for a real Trivy image report. */
export const MAX_SCAN_PAYLOAD_BYTES = 8 * 1024 * 1024;

/**
 * Repository and branch names are echoed into the UI and used as filter keys.
 * Constrain them to the characters GitHub actually permits so nothing exotic
 * reaches a href or a filter value.
 */
const repositoryName = z
  .string()
  .min(1)
  .max(200)
  .regex(
    /^[A-Za-z0-9._\-/]+$/,
    "repositoryName may contain letters, digits, '.', '_', '-' and '/' only",
  );

const branchName = z.string().min(1).max(255).regex(
  /^[^\s~^:?*[\]\\]+$/,
  "branch contains characters that are invalid in a git ref",
);

const commitSha = z
  .string()
  .regex(/^[0-9a-fA-F]{7,64}$/, "commitSha must be a hex git object id");

const identifier = z.string().min(1).max(200);

const isoTimestamp = z
  .string()
  .refine(
    (value) => !Number.isNaN(Date.parse(value)),
    "must be an ISO 8601 timestamp",
  );

/**
 * Ingestion request.
 *
 * Note what is absent: there is no path, filename or URL field anywhere. The
 * dashboard never reads a file the caller names and never fetches a URL the
 * caller supplies — the scan output travels in the request body or not at all.
 */
export const scanIngestionRequestSchema = z.object({
  scanner: z.enum(SCANNER_TYPES),
  format: z.enum(["sarif", "json"]).optional(),

  repositoryId: identifier.optional(),
  repositoryName: repositoryName.optional(),
  branch: branchName.optional(),
  commitSha: commitSha.optional(),

  workflowRunId: identifier.optional(),
  workflowRunUrl: z
    .url()
    .max(2048)
    .refine(
      (value) => value.startsWith("https://"),
      "workflowRunUrl must be https",
    )
    .optional(),

  applicationId: identifier.optional(),
  environment: z.string().min(1).max(100).optional(),

  scannedAt: isoTimestamp.optional(),

  // Intentionally `unknown`: adapters own the shape.
  results: z.unknown(),

  autoResolveMissing: z.boolean().optional(),
});

export type ScanIngestionRequestInput = z.infer<
  typeof scanIngestionRequestSchema
>;

/** Comma-separated query parameter -> array of allowed enum values. */
function csvEnum<T extends readonly [string, ...string[]]>(values: T) {
  return z
    .string()
    .optional()
    .transform((value) =>
      value
        ? value
            .split(",")
            .map((entry) => entry.trim().toUpperCase())
            .filter((entry) => entry !== "")
        : undefined,
    )
    .pipe(z.array(z.enum(values)).optional());
}

function csvString() {
  return z
    .string()
    .optional()
    .transform((value) =>
      value
        ? value
            .split(",")
            .map((entry) => entry.trim())
            .filter((entry) => entry !== "")
        : undefined,
    )
    .pipe(z.array(z.string().max(200)).max(50).optional());
}

export const findingQuerySchema = z.object({
  severity: csvEnum(SEVERITIES),
  scanner: csvEnum(SCANNER_TYPES),
  category: csvEnum(FINDING_CATEGORIES),
  status: csvEnum(FINDING_STATUSES),
  repository: csvString(),
  environment: csvString(),
  search: z.string().max(200).optional(),
  timeframe: z.enum(["24h", "7d", "30d", "all"]).optional(),
  page: z.coerce.number().int().min(1).max(10_000).optional(),
  pageSize: z.coerce.number().int().min(1).max(200).optional(),
  sortBy: z
    .enum(["severity", "lastDetectedAt", "firstDetectedAt", "title"])
    .optional(),
  sortDirection: z.enum(["asc", "desc"]).optional(),
});

export const scanRunQuerySchema = z.object({
  scanner: csvEnum(SCANNER_TYPES),
  status: csvEnum(SCAN_RUN_STATUSES),
  repository: csvString(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

export const statisticsQuerySchema = z.object({
  severity: csvEnum(SEVERITIES),
  scanner: csvEnum(SCANNER_TYPES),
  category: csvEnum(FINDING_CATEGORIES),
  status: csvEnum(FINDING_STATUSES),
  repository: csvString(),
  environment: csvString(),
  timeframe: z.enum(["24h", "7d", "30d", "all"]).optional(),
  trendDays: z.coerce.number().int().min(1).max(365).optional(),
});

/** Turn URLSearchParams into the plain object the schemas expect. */
export function searchParamsToObject(
  params: URLSearchParams,
): Record<string, string> {
  const output: Record<string, string> = {};
  params.forEach((value, key) => {
    output[key] = value;
  });
  return output;
}

/** Flatten a ZodError into a compact, safe-to-return message list. */
export function formatZodIssues(error: z.ZodError): string[] {
  return error.issues.map((issue) => {
    const path = issue.path.join(".");
    return path ? `${path}: ${issue.message}` : issue.message;
  });
}
