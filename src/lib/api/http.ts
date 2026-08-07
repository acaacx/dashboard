import { timingSafeEqual } from "node:crypto";

import { isSecurityDomainError } from "@/domain/security/errors";
import { MAX_SCAN_PAYLOAD_BYTES } from "@/lib/security/validation/schemas";

/**
 * HTTP helpers for the security API.
 *
 * Centralised so every route returns errors in the same shape and, more
 * importantly, so no route can accidentally return an internal error message or
 * a fragment of a scanner payload to a caller.
 */

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      // These payloads are per-request and access-controlled; never let a
      // shared cache hold them.
      "cache-control": "no-store",
    },
  });
}

export function errorResponse(
  code: string,
  message: string,
  status: number,
  details?: string[],
): Response {
  return jsonResponse({ error: { code, message, details } }, status);
}

/** Map any thrown value onto a safe HTTP response. */
export function errorToResponse(error: unknown): Response {
  if (isSecurityDomainError(error)) {
    return errorResponse(error.code, error.message, error.httpStatus);
  }
  // Deliberately opaque: an unexpected error's message may contain payload
  // fragments or internal paths.
  return errorResponse(
    "INTERNAL_ERROR",
    "The request could not be processed.",
    500,
  );
}

/** Constant-time string comparison that tolerates differing lengths. */
function safeEqual(a: string, b: string): boolean {
  const bufferA = Buffer.from(a, "utf8");
  const bufferB = Buffer.from(b, "utf8");
  if (bufferA.length !== bufferB.length) return false;
  return timingSafeEqual(bufferA, bufferB);
}

export type AuthResult =
  | { ok: true }
  | { ok: false; response: Response };

/**
 * Bearer-token gate for scan ingestion.
 *
 * The token lives in `SECURITY_INGEST_TOKEN` and is compared in constant time.
 * When the variable is unset the endpoint is refused outright in production and
 * allowed only in development, so an unconfigured deployment fails closed
 * rather than accepting anonymous writes.
 *
 * This is deliberately the simplest thing that is actually safe. For a real
 * deployment, see README "Scan ingestion — authentication" for the upgrade path
 * (per-repository tokens, OIDC from GitHub Actions).
 */
export function requireIngestAuth(request: Request): AuthResult {
  const expected = process.env.SECURITY_INGEST_TOKEN;

  if (!expected) {
    if (process.env.NODE_ENV === "production") {
      return {
        ok: false,
        response: errorResponse(
          "INGESTION_NOT_CONFIGURED",
          "Scan ingestion is disabled because SECURITY_INGEST_TOKEN is not set.",
          503,
        ),
      };
    }
    return { ok: true };
  }

  const header = request.headers.get("authorization") ?? "";
  const [scheme, token] = header.split(" ");

  if (scheme?.toLowerCase() !== "bearer" || !token || !safeEqual(token, expected)) {
    return {
      ok: false,
      response: errorResponse(
        "UNAUTHORIZED",
        "A valid bearer token is required.",
        401,
      ),
    };
  }

  return { ok: true };
}

export type BodyResult =
  | { ok: true; value: unknown }
  | { ok: false; response: Response };

/**
 * Read and parse a JSON body with a hard size ceiling.
 *
 * The Content-Length header is checked first as a cheap rejection, then the
 * actual decoded body is measured, because Content-Length can lie.
 */
export async function readJsonBody(
  request: Request,
  limitBytes = MAX_SCAN_PAYLOAD_BYTES,
): Promise<BodyResult> {
  const declaredLength = Number(request.headers.get("content-length") ?? "");
  if (Number.isFinite(declaredLength) && declaredLength > limitBytes) {
    return {
      ok: false,
      response: errorResponse(
        "PAYLOAD_TOO_LARGE",
        `Request body exceeds the ${limitBytes} byte limit.`,
        413,
      ),
    };
  }

  let raw: string;
  try {
    raw = await request.text();
  } catch {
    return {
      ok: false,
      response: errorResponse("INVALID_BODY", "Could not read request body.", 400),
    };
  }

  if (Buffer.byteLength(raw, "utf8") > limitBytes) {
    return {
      ok: false,
      response: errorResponse(
        "PAYLOAD_TOO_LARGE",
        `Request body exceeds the ${limitBytes} byte limit.`,
        413,
      ),
    };
  }

  try {
    return { ok: true, value: JSON.parse(raw) };
  } catch {
    return {
      ok: false,
      response: errorResponse(
        "INVALID_JSON",
        "Request body is not valid JSON.",
        400,
      ),
    };
  }
}
