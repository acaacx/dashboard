import { NextResponse, type NextRequest } from "next/server";

import { SESSION_COOKIE_NAME } from "@/lib/auth/cookie";

/**
 * NOT A SECURITY BOUNDARY.
 *
 * This file checks that a session cookie is *present*, never that it is valid.
 * It exists so an anonymous navigation lands on the login page without first
 * flashing the dashboard shell.
 *
 * Every real check happens at the boundary itself — `requireUser()` in the
 * layout and in each page, `protectedRoute()` on each API route. That is not
 * belt-and-braces; the Next.js documentation for this file is explicit that a
 * matcher change or a refactor that moves a Server Function to a different
 * route can silently remove Proxy coverage, and that authentication must be
 * verified inside each Server Function rather than here.
 *
 * Proxy also warns against depending on shared modules or globals, and this
 * application's container is cached on globalThis. So no store is touched here.
 *
 * `middleware.ts` was renamed to `proxy.ts` in Next.js 16. Do not add a
 * `runtime` export — setting it in a Proxy file throws.
 */

const PROTECTED_PREFIX = "/dashboard";

export function proxy(request: NextRequest): NextResponse {
  const { pathname, search } = request.nextUrl;

  // The matcher below already scopes this to /dashboard, but the check is
  // repeated here so the function is correct on its own terms: the login page
  // must never redirect to itself, and the API answers 401 rather than sending
  // a script to an HTML form.
  if (pathname !== PROTECTED_PREFIX && !pathname.startsWith(`${PROTECTED_PREFIX}/`)) {
    return NextResponse.next();
  }

  if (request.cookies.has(SESSION_COOKIE_NAME)) return NextResponse.next();

  const login = new URL("/login", request.url);
  login.searchParams.set("next", `${pathname}${search}`);

  return NextResponse.redirect(login);
}

export const config = {
  // Dashboard navigations only. The API answers 401 rather than redirecting —
  // a script following a redirect to an HTML login page gets a confusing 200.
  matcher: ["/dashboard/:path*"],
};
