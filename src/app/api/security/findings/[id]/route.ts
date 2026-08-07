import { errorResponse, errorToResponse, jsonResponse } from "@/lib/api/http";
import { getSecurityService } from "@/lib/security/container";

/** GET /api/security/findings/:id */
export async function GET(
  _request: Request,
  context: { params: Promise<{ id: string }> },
): Promise<Response> {
  try {
    const { id } = await context.params;

    const service = await getSecurityService();
    const finding = await service.getFindingById(id);

    if (!finding) {
      return errorResponse("NOT_FOUND", "Finding not found.", 404);
    }

    return jsonResponse({ finding });
  } catch (error) {
    return errorToResponse(error);
  }
}
