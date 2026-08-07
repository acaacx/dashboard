import type { ReactNode } from "react";

export function PageHeader({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <header className="relative mb-6">
      {/* Hairline grid, masked to fade out — depth without a gradient. */}
      <div
        aria-hidden
        className="console-grid pointer-events-none absolute -inset-x-8 -top-8 h-32 opacity-40"
      />
      <div className="relative flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-ink text-xl font-semibold tracking-tight">
            {title}
          </h1>
          {subtitle && (
            <p className="text-ink-muted mt-1 text-sm">{subtitle}</p>
          )}
        </div>
        {action}
      </div>
    </header>
  );
}
