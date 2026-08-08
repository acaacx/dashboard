/**
 * Form state shared by the action and the client form.
 *
 * Its own module, free of `"use server"`, so the client component can import
 * the type without pulling a server runtime into the browser bundle — the same
 * split as `src/lib/security/status-change.ts`.
 */
export interface SignInState {
  error?: string;
}
