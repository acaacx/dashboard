"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_ITEMS = [
  { href: "/dashboard", label: "Overview", key: "overview" },
  { href: "/dashboard/security", label: "Security", key: "security" },
  { href: "/dashboard/applications", label: "Applications", key: "apps" },
  { href: "/dashboard/pipelines", label: "Pipelines", key: "pipelines" },
] as const;

export function SidebarNav() {
  const pathname = usePathname();

  return (
    <nav aria-label="Primary" className="flex flex-col gap-0.5">
      {NAV_ITEMS.map((item) => {
        const active =
          item.href === "/dashboard"
            ? pathname === "/dashboard"
            : pathname.startsWith(item.href);

        return (
          <Link
            key={item.key}
            href={item.href}
            aria-current={active ? "page" : undefined}
            className={`group relative rounded px-3 py-2 text-sm transition-colors ${
              active
                ? "bg-surface-raised text-ink"
                : "text-ink-muted hover:bg-surface hover:text-ink"
            }`}
          >
            {/* The accent appears only on the active item — one accent, used sparingly. */}
            <span
              aria-hidden
              className={`bg-accent absolute top-1/2 left-0 h-4 w-0.5 -translate-y-1/2 rounded-full transition-opacity ${
                active ? "opacity-100" : "opacity-0"
              }`}
            />
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
