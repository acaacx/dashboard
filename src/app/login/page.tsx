import { redirect } from "next/navigation";

import { getAuthContainer } from "@/lib/auth/container";
import { getSessionUser } from "@/lib/auth/guards";
import { safeNextPath } from "@/lib/auth/safe-next";
import { LoginForm } from "./login-form";

/**
 * Login screen — the one page outside the wall.
 *
 * force-dynamic for the same reason the dashboard pages are: a prerendered
 * login page would serve build-time state forever, including the "no accounts
 * exist" notice.
 */
export const dynamic = "force-dynamic";

export default async function LoginPage({ searchParams }: PageProps<"/login">) {
  const params = await searchParams;
  const next = safeNextPath(
    typeof params.next === "string" ? params.next : undefined,
  );

  // Already signed in: no reason to show a login form.
  if (await getSessionUser()) redirect(next);

  const { users } = await getAuthContainer();
  const hasAccounts = (await users.count()) > 0;

  return (
    <main className="mx-auto flex min-h-dvh w-full max-w-sm flex-col justify-center px-6">
      <h1 className="text-ink text-lg font-semibold tracking-tight">DevSecOps</h1>
      <p className="text-ink-faint mb-7 font-mono text-[10px] tracking-[0.18em] uppercase">
        Control Plane
      </p>

      {hasAccounts ? (
        <LoginForm next={next} />
      ) : (
        <div className="border-line bg-surface/60 rounded border p-4">
          <p className="text-ink text-sm">No accounts exist yet.</p>
          <p className="text-ink-faint mt-2 text-sm">
            Create one, then sign in:
          </p>
          <pre className="text-ink-faint mt-3 overflow-x-auto font-mono text-xs">
            npm run user -- create --email you@example.com --role approver
          </pre>
        </div>
      )}
    </main>
  );
}
