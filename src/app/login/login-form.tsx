"use client";

import { useActionState } from "react";

import { signInAction } from "./actions";
import type { SignInState } from "./form-state";

const INITIAL: SignInState = {};

export function LoginForm({ next }: { next: string }) {
  const [state, formAction, pending] = useActionState(signInAction, INITIAL);

  return (
    <form action={formAction} className="flex flex-col gap-4">
      <input type="hidden" name="next" value={next} />

      <label className="flex flex-col gap-1.5">
        <span className="text-ink-faint font-mono text-[10px] tracking-[0.18em] uppercase">
          Email
        </span>
        <input
          name="email"
          type="email"
          autoComplete="username"
          required
          className="border-line bg-surface text-ink focus:border-accent rounded border px-3 py-2 text-sm outline-none"
        />
      </label>

      <label className="flex flex-col gap-1.5">
        <span className="text-ink-faint font-mono text-[10px] tracking-[0.18em] uppercase">
          Password
        </span>
        <input
          name="password"
          type="password"
          autoComplete="current-password"
          required
          className="border-line bg-surface text-ink focus:border-accent rounded border px-3 py-2 text-sm outline-none"
        />
      </label>

      {state.error && (
        <p role="alert" className="text-sm text-[var(--severity-high)]">
          {state.error}
        </p>
      )}

      <button
        type="submit"
        disabled={pending}
        className="bg-accent mt-1 rounded px-3 py-2 text-sm font-medium text-black disabled:opacity-60"
      >
        {pending ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
