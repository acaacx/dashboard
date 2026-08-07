import type { ReactNode } from "react";

interface StatProps {
  label: string;
  value: number | string;
  /** Short qualifier under the value, e.g. "of 28 total". */
  hint?: string;
  /** Tailwind text colour class for the value, e.g. `text-critical`. */
  tone?: string;
  icon?: ReactNode;
}

/**
 * Compact metric tile. Value uses tabular mono so a column of numbers lines up
 * digit for digit — the whole point of a dense ops view.
 */
export function Stat({ label, value, hint, tone = "text-ink" }: StatProps) {
  return (
    <div className="border-line bg-surface rounded-[var(--radius-panel)] border px-4 py-3.5">
      <p className="text-ink-faint font-mono text-[10px] font-medium tracking-[0.14em] uppercase">
        {label}
      </p>
      <p className={`numeric mt-2 text-2xl leading-none font-medium ${tone}`}>
        {value}
      </p>
      {hint && <p className="text-ink-faint mt-1.5 text-xs">{hint}</p>}
    </div>
  );
}
