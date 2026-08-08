"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { isAuthDomainError } from "@/domain/auth/errors";
import {
  buildClearedSessionCookie,
  buildSessionCookie,
  SESSION_COOKIE_NAME,
} from "@/lib/auth/cookie";
import { getAuthService } from "@/lib/auth/container";
import { safeNextPath } from "@/lib/auth/safe-next";
import type { SignInState } from "./form-state";

/**
 * Sign in.
 *
 * A Server Action rather than a REST route: no credential reaches client
 * JavaScript, and there is no public endpoint accepting passwords.
 *
 * Failures come back as state, never as a throw. Only domain errors — which are
 * safe by construction and never carry a credential — pass their message
 * through; anything else is flattened, because an unexpected error's message
 * can contain an internal hostname.
 */
export async function signInAction(
  _previous: SignInState,
  formData: FormData,
): Promise<SignInState> {
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const next = safeNextPath(String(formData.get("next") ?? ""));

  if (!email || !password) {
    return { error: "Enter an email and a password." };
  }

  let cookieValue: string;

  try {
    const service = await getAuthService();
    const { token, expiresAt } = await service.authenticate(email, password);
    cookieValue = buildSessionCookie(token, expiresAt);
  } catch (error) {
    if (isAuthDomainError(error)) return { error: error.message };
    return { error: "Sign-in is unavailable. Try again shortly." };
  }

  await setRawCookie(cookieValue);

  // Outside the try: redirect() signals by throwing, and catching it here would
  // turn a successful sign-in into "Sign-in is unavailable".
  redirect(next);
}

export async function signOutAction(): Promise<void> {
  const store = await cookies();
  const token = store.get(SESSION_COOKIE_NAME)?.value;

  if (token) {
    // Delete the row, not just the cookie. Clearing the cookie alone leaves a
    // copied token working until it expires.
    await (await getAuthService()).signOut(token);
  }

  await setRawCookie(buildClearedSessionCookie());
  redirect("/login");
}

/**
 * Apply a fully-formed Set-Cookie string through the cookie jar.
 *
 * The attributes are built in one place (`src/lib/auth/cookie.ts`) so the
 * action, a future route and the tests cannot drift on HttpOnly or SameSite.
 */
async function setRawCookie(setCookie: string): Promise<void> {
  const [pair, ...rest] = setCookie.split("; ");
  const separator = pair!.indexOf("=");
  const name = pair!.slice(0, separator);
  const value = pair!.slice(separator + 1);

  const attributes = new Map(
    rest.map((part) => {
      const index = part.indexOf("=");
      return index === -1
        ? ([part.toLowerCase(), "true"] as const)
        : ([part.slice(0, index).toLowerCase(), part.slice(index + 1)] as const);
    }),
  );

  const store = await cookies();
  store.set({
    name,
    value,
    path: "/",
    httpOnly: attributes.has("httponly"),
    secure: attributes.has("secure"),
    sameSite: "lax",
    maxAge: Number(attributes.get("max-age") ?? 0),
  });
}
