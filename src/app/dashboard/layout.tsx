import Link from "next/link";

import { signOutAction } from "@/app/login/actions";
import { SidebarNav } from "@/components/shell/sidebar-nav";
import { MockBadge } from "@/components/ui/badge";
import { requireUser } from "@/lib/auth/guards";
import { getSecurityContainer } from "@/lib/security/container";

export default async function DashboardLayout({
  children,
}: LayoutProps<"/dashboard">) {
  // Redirects when absent. Not sufficient on its own — a layout does not re-run
  // on every client-side navigation — so each page calls requireUser() too.
  const user = await requireUser();
  const { usingMockData } = await getSecurityContainer();

  return (
    <div className="flex min-h-full">
      <aside className="border-line bg-surface/60 sticky top-0 hidden h-dvh w-56 shrink-0 flex-col border-r px-3 py-5 md:flex">
        <Link href="/dashboard" className="mb-7 block px-3">
          <span className="text-ink block text-sm font-semibold tracking-tight">
            DevSecOps
          </span>
          <span className="text-ink-faint block font-mono text-[10px] tracking-[0.18em] uppercase">
            Control Plane
          </span>
        </Link>

        <SidebarNav />

        <div className="mt-auto px-3">
          {usingMockData && <MockBadge />}

          <p
            className="text-ink-faint mt-3 truncate font-mono text-[10px]"
            title={user.email}
          >
            {user.email}
          </p>

          <form action={signOutAction}>
            <button
              type="submit"
              className="text-ink-faint hover:text-ink mt-1 font-mono text-[10px] tracking-[0.18em] uppercase"
            >
              Sign out
            </button>
          </form>

          <p className="text-ink-faint mt-3 font-mono text-[10px] leading-relaxed">
            Semgrep · Trivy
            <br />
            Checkov · Gitleaks
          </p>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        {/* Mobile nav: the sidebar collapses to a horizontal strip. */}
        <div className="border-line bg-surface/60 sticky top-0 z-10 border-b px-4 py-3 backdrop-blur md:hidden">
          <SidebarNav />
        </div>
        <main className="mx-auto w-full max-w-[1400px] px-4 py-6 md:px-8 md:py-8">
          {children}
        </main>
      </div>
    </div>
  );
}
