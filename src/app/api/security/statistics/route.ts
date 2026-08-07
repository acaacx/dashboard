import { errorResponse, errorToResponse, jsonResponse } from "@/lib/api/http";
import { getSecurityService } from "@/lib/security/container";
import {
  formatZodIssues,
  searchParamsToObject,
  statisticsQuerySchema,
} from "@/lib/security/validation/schemas";

/**
 * GET /api/security/statistics
 *
 * Returns the aggregate the dashboard renders: severity/scanner/category/
 * repository/environment breakdowns over OPEN findings, lifecycle totals, new
 * and resolved counts for the timeframe, MTTR, plus the trend series.
 *
 * All arithmetic happens in the service and repository — this route only
 * validates input and serialises the answer.
 */
export async function GET(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    const parsed = statisticsQuerySchema.safeParse(
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

    const { timeframe = "all", trendDays = 30, ...filters } = parsed.data;

    const service = await getSecurityService();
    const [statistics, trend, scannerHealth] = await Promise.all([
      service.getStatistics(filters, timeframe),
      service.getTrend(trendDays, filters),
      service.getScannerHealth(),
    ]);

    return jsonResponse({ statistics, trend, scannerHealth, timeframe });
  } catch (error) {
    return errorToResponse(error);
  }
}
