import { errorResponse, errorToResponse, jsonResponse } from "@/lib/api/http";
import { protectedRoute } from "@/lib/auth/guards";
import { getSecurityService } from "@/lib/security/container";

/**
 * GET /api/security/findings/:id/history
 *
 * The append-only decision trail for one finding, newest first. Requires a
 * session and nothing more: a viewer who may read a finding's current
 * justification may read its previous ones — requireApprover() guards writing
 * decisions, not reading them.
 *
 * 404 mirrors the sibling finding route, so the two endpoints leak existence
 * identically.
 */
export const GET = protectedRoute<{ params: Promise<{ id: string }> }>(
  async (_request, { routeContext }): Promise<Response> => {
    try {
      const { id } = await routeContext.params;

      const service = await getSecurityService();
      const decisions = await service.getDecisionHistory(id);

      if (decisions === null) {
        return errorResponse("NOT_FOUND", "Finding not found.", 404);
      }

      return jsonResponse({ decisions });
    } catch (error) {
      return errorToResponse(error);
    }
  },
);
