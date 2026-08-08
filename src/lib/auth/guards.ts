import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { ForbiddenError, NotAuthenticatedError } from "@/domain/auth/errors";
import { isApprover, type SessionUser } from "@/domain/auth/user";
import { errorResponse } from "@/lib/api/http";
import { getAuthService } from "./container";
import { readSessionCookie, SESSION_COOKIE_NAME } from "./cookie";

/**
 * Authentication at the boundaries.
 *
 * Next.js 16 renamed `middleware.ts` to `proxy.ts` and moved it to the Node
 * runtime, so a session could technically be validated there. The framework's
 * own documentation says not to rely on it: a matcher change or a refactor that
 * moves a Server Function silently removes Proxy coverage. So `src/proxy.ts`
 * only redirects for UX, and every boundary validates for itself here.
 *
 * There are two entry points because there are two shapes of caller. Route
 * handlers hold a Request and parse its Cookie header, which also means their
 * tests can call them with a plain Request and no Next runtime. Server
 * components hold no Request and read the cookie store instead.
 */

/** Never distinguishes absent, expired, forged, or belonging-to-a-deleted-user. */
export async function getSessionUserFromRequest(
  request: Request,
): Promise<SessionUser | null> {
  const token = readSessionCookie(request.headers.get("cookie"));
  if (!token) return null;

  try {
    return await (await getAuthService()).resolveToken(token);
  } catch {
    // Fail closed. An unreachable store means "not authenticated", never
    // "authenticated" — an auth check that fails open during an outage is
    // worse than no check, because it looks like one.
    return null;
  }
}

/**
 * Wrap a route handler so it cannot run without a session.
 *
 * The session is an argument rather than something the handler fetches, so
 * forgetting the wrapper is a type error at the call site rather than a route
 * that is silently public.
 *
 * Generic over the route context so a dynamic segment keeps its types: a
 * `[id]` route declares `protectedRoute<{ params: Promise<{ id: string }> }>`
 * and reads `routeContext.params` with no cast.
 */
export function protectedRoute<Context = unknown>(
  handler: (
    request: Request,
    context: { user: SessionUser; routeContext: Context },
  ) => Promise<Response>,
): (request: Request, routeContext?: Context) => Promise<Response> {
  // routeContext is optional so a static route can be called with the request
  // alone, in a test or by Next. Next always supplies it for dynamic segments.
  //
  // The default is `unknown` rather than `undefined` because Next 16's generated
  // route validator types every handler — static routes included — as receiving
  // a `{ params }` context. A handler declaring that parameter as `undefined`
  // fails that check even though it never reads it.
  return async (request: Request, routeContext?: Context) => {
    const user = await getSessionUserFromRequest(request);

    if (!user) {
      return errorResponse("UNAUTHORIZED", "Authentication is required.", 401);
    }

    return handler(request, { user, routeContext: routeContext as Context });
  };
}

/** Server-component and Server-Action path. Null when not signed in. */
export async function getSessionUser(): Promise<SessionUser | null> {
  const store = await cookies();
  const token = store.get(SESSION_COOKIE_NAME)?.value;
  if (!token) return null;

  try {
    return await (await getAuthService()).resolveToken(token);
  } catch {
    return null;
  }
}

/**
 * Require a session in a server component.
 *
 * Redirects to the plain login page rather than building a `?next=`: a server
 * component has no reliable view of the current URL, and `src/proxy.ts` — which
 * does — adds the parameter for navigations it intercepts.
 *
 * `redirect()` throws, so this never returns null.
 */
export async function requireUser(): Promise<SessionUser> {
  const user = await getSessionUser();
  if (!user) redirect("/login");
  return user;
}

/**
 * Require an approver in a Server Action.
 *
 * Throws instead of redirecting like `requireUser`, because an action's caller
 * is a fetch rather than a navigation: the action maps `AuthDomainError` to its
 * `{ ok: false, code, message }` result and the drawer renders it.
 *
 * Not redundant with the UI. `canDecide` decides what renders; a select element
 * is not a security boundary, exactly as the manual-RESOLVED ban is enforced
 * here as well as hidden there.
 */
export async function requireApprover(): Promise<SessionUser> {
  const user = await getSessionUser();
  if (!user) throw new NotAuthenticatedError();
  if (!isApprover(user)) throw new ForbiddenError();
  return user;
}
