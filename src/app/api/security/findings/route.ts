import type { FindingQuery } from "@/domain/security/finding";
import { errorResponse, errorToResponse, jsonResponse } from "@/lib/api/http";
import { protectedRoute } from "@/lib/auth/guards";
import { getSecurityService } from "@/lib/security/container";
import { timeframeCutoff } from "@/lib/security/services/security-service";
import {
  findingQuerySchema,
  formatZodIssues,
  searchParamsToObject,
} from "@/lib/security/validation/schemas";

/**
 * GET /api/security/findings
 *
 * Filtering, sorting and pagination all happen server-side; the response is one
 * page of normalized findings. Supported parameters are documented in the
 * README ("API").
 *
 * Requires a session. This list names real vulnerabilities in real
 * repositories, so an anonymous read API would be a bypass around the UI's
 * login wall rather than a convenience.
 */
export const GET = protectedRoute(async (request: Request): Promise<Response> => {
  try {
    const url = new URL(request.url);
    const parsed = findingQuerySchema.safeParse(
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

    const {
      timeframe,
      page,
      pageSize,
      sortBy,
      sortDirection,
      ...filters
    } = parsed.data;

    const query: FindingQuery = {
      ...filters,
      detectedSince: timeframe ? timeframeCutoff(timeframe) : undefined,
      page,
      pageSize,
      sortBy,
      sortDirection,
    };

    const service = await getSecurityService();
    return jsonResponse(await service.getFindings(query));
  } catch (error) {
    return errorToResponse(error);
  }
});
