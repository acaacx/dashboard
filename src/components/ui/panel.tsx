import type { ReactNode } from "react";

interface PanelProps {
  title?: string;
  /** Small uppercase label above the title, e.g. a section kicker. */
  eyebrow?: string;
  description?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  /** Remove inner padding when the child manages its own (tables). */
  flush?: boolean;
}

/**
 * The single container primitive. Every card, chart and table on the dashboard
 * sits in one of these, which is what keeps the surface hierarchy consistent:
 * canvas -> panel -> raised element.
 */
export function Panel({
  title,
  eyebrow,
  description,
  action,
  children,
  className = "",
  flush = false,
}: PanelProps) {
  return (
    <section
      className={`border-line bg-surface rounded-[var(--radius-panel)] border ${className}`}
    >
      {(title || action) && (
        <header className="border-line flex items-start justify-between gap-4 border-b px-5 py-4">
          <div className="min-w-0">
            {eyebrow && (
              <p className="text-ink-faint mb-1 font-mono text-[10px] font-medium tracking-[0.14em] uppercase">
                {eyebrow}
              </p>
            )}
            {title && (
              <h2 className="text-ink truncate text-sm font-semibold">
                {title}
              </h2>
            )}
            {description && (
              <p className="text-ink-muted mt-1 text-xs">{description}</p>
            )}
          </div>
          {action && <div className="shrink-0">{action}</div>}
        </header>
      )}
      <div className={flush ? "" : "p-5"}>{children}</div>
    </section>
  );
}

export function EmptyState({
  title,
  hint,
}: {
  title: string;
  hint?: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 px-4 py-12 text-center">
      <p className="text-ink-muted text-sm">{title}</p>
      {hint && <p className="text-ink-faint max-w-md text-xs">{hint}</p>}
    </div>
  );
}
