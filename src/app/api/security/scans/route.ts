import {
  errorResponse,
  errorToResponse,
  jsonResponse,
  readJsonBody,
  requireIngestAuth,
} from "@/lib/api/http";
import { getSecurityContainer } from "@/lib/security/container";
import {
  formatZodIssues,
  scanIngestionRequestSchema,
  scanRunQuerySchema,
  searchParamsToObject,
} from "@/lib/security/validation/schemas";

/**
 * GET /api/security/scans — recent scan runs, which is what scanner health and
 * the pipeline view are built from.
 */
export async function GET(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    const parsed = scanRunQuerySchema.safeParse(
      searchParamsToObject(url.searchParams),
    );

    if (!parsed.success) {
      return errorResponse(
        "INVALID_QUERY",
        "One or more query parameters are invalid.",
        400,
        formatZodIssues(parsed.error),
      );
    }

    const { scanner, status, repository, limit = 50 } = parsed.data;

    const { securityService } = await getSecurityContainer();
    const [runs, health] = await Promise.all([
      securityService.getScanRuns({
        scanner,
        status,
        repositoryName: repository,
        limit,
      }),
      securityService.getScannerHealth(),
    ]);

    return jsonResponse({ runs, health });
  } catch (error) {
    return errorToResponse(error);
  }
}

/**
 * POST /api/security/scans — scan ingestion.
 *
 * Security posture for this endpoint:
 *  - bearer token required (fails closed in production when unconfigured)
 *  - body size capped before parsing
 *  - envelope validated with Zod; repository, branch and commit are pattern-
 *    constrained
 *  - the scanner payload itself is passed to adapters as `unknown` and parsed
 *    defensively — a malformed report produces a FAILED ScanRun, never a crash
 *  - no field accepts a filesystem path or a URL to fetch: results travel in
 *    the body only
 */
export async function POST(request: Request): Promise<Response> {
  const auth = requireIngestAuth(request);
  if (!auth.ok) return auth.response;

  const body = await readJsonBody(request);
  if (!body.ok) return body.response;

  const parsed = scanIngestionRequestSchema.safeParse(body.value);
  if (!parsed.success) {
    return errorResponse(
      "INVALID_REQUEST",
      "The scan submission is invalid.",
      400,
      formatZodIssues(parsed.error),
    );
  }

  try {
    const { ingestionService } = await getSecurityContainer();
    const result = await ingestionService.ingest(parsed.data);

    return jsonResponse(
      {
        scanRunId: result.scanRun.id,
        scanner: result.scanRun.scanner,
        status: result.scanRun.status,
        summary: result.summary,
      },
      201,
    );
  } catch (error) {
    return errorToResponse(error);
  }
}
