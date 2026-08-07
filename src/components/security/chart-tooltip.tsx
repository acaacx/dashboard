"use client";

import type { ReactNode } from "react";

/**
 * Shared tooltip surface for every chart, so a hovered bar and a hovered donut
 * segment look identical. Recharts' default tooltip is white-on-white here.
 */
export function ChartTooltipShell({ children }: { children: ReactNode }) {
  return (
    <div className="border-line-strong bg-surface-raised rounded border px-2.5 py-1.5 shadow-lg">
      {children}
    </div>
  );
}

interface TooltipPayloadEntry {
  name?: string | number;
  value?: string | number;
  color?: string;
  payload?: { color?: string; label?: string };
}

export function SimpleTooltip({
  active,
  payload,
  label,
  valueSuffix = "",
}: {
  active?: boolean;
  payload?: TooltipPayloadEntry[];
  label?: string | number;
  valueSuffix?: string;
}) {
  if (!active || !payload?.length) return null;

  return (
    <ChartTooltipShell>
      {label !== undefined && (
        <p className="text-ink-faint mb-1 font-mono text-[10px] tracking-wide uppercase">
          {label}
        </p>
      )}
      <ul className="space-y-0.5">
        {payload.map((entry, index) => (
          <li
            key={`${entry.name}-${index}`}
            className="flex items-center gap-2 text-xs"
          >
            <span
              aria-hidden
              className="size-2 shrink-0 rounded-[2px]"
              style={{
                background: entry.payload?.color ?? entry.color ?? "currentColor",
              }}
            />
            <span className="text-ink-muted">
              {entry.payload?.label ?? entry.name}
            </span>
            <span className="numeric text-ink ml-auto">
              {entry.value}
              {valueSuffix}
            </span>
          </li>
        ))}
      </ul>
    </ChartTooltipShell>
  );
}
