import { errorResponse, errorToResponse, jsonResponse } from "@/lib/api/http";
import { protectedRoute } from "@/lib/auth/guards";
import { getSecurityService } from "@/lib/security/container";

/**
 * GET /api/security/findings/:id
 *
 * Requires a session, like the collection route it belongs to — an anonymous
 * detail endpoint would hand out exactly what the list endpoint refuses.
 */
export const GET = protectedRoute<{ params: Promise<{ id: string }> }>(
  async (_request, { routeContext }): Promise<Response> => {
    try {
      const { id } = await routeContext.params;

      const service = await getSecurityService();
      const finding = await service.getFindingById(id);

      if (!finding) {
        return errorResponse("NOT_FOUND", "Finding not found.", 404);
      }

      return jsonResponse({ finding });
    } catch (error) {
      return errorToResponse(error);
    }
  },
);
