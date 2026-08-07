"use client";

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

import {
  CHARTED_SEVERITIES,
  severityLabel,
  type Severity,
} from "@/domain/security/enums";
import type { SeverityCounts } from "@/domain/security/finding";
import { SEVERITY_CHART_COLOR } from "./severity-tokens";
import { SimpleTooltip } from "./chart-tooltip";

/**
 * Findings-by-severity donut.
 *
 * Receives counts that the service already computed over OPEN findings only —
 * this component does no filtering, no status logic and no arithmetic beyond
 * summing what it was given for the centre label.
 */
export function SeverityDonut({
  counts,
  size = 168,
  showLegend = true,
}: {
  counts: SeverityCounts;
  size?: number;
  showLegend?: boolean;
}) {
  const slices = CHARTED_SEVERITIES.map((severity) => ({
    key: severity,
    label: severityLabel(severity),
    value: counts[severity],
    color: SEVERITY_CHART_COLOR[severity],
  }));

  const total = slices.reduce((sum, slice) => sum + slice.value, 0);
  const nonZero = slices.filter((slice) => slice.value > 0);

  return (
    <div className="flex flex-wrap items-center gap-6">
      <div
        className="relative shrink-0"
        style={{ width: size, height: size }}
        role="img"
        aria-label={`${total} open findings: ${slices
          .map((slice) => `${slice.value} ${slice.label}`)
          .join(", ")}`}
      >
        {nonZero.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={nonZero}
                dataKey="value"
                nameKey="label"
                innerRadius="66%"
                outerRadius="100%"
                paddingAngle={nonZero.length > 1 ? 2 : 0}
                startAngle={90}
                endAngle={-270}
                stroke="none"
                isAnimationActive={false}
              >
                {nonZero.map((slice) => (
                  <Cell key={slice.key} fill={slice.color} />
                ))}
              </Pie>
              <Tooltip content={<SimpleTooltip />} cursor={false} />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <div className="border-line absolute inset-0 rounded-full border-8" />
        )}

        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="numeric text-ink text-3xl leading-none font-medium">
            {total}
          </span>
          <span className="text-ink-faint mt-1 font-mono text-[10px] tracking-[0.12em] uppercase">
            Open
          </span>
        </div>
      </div>

      {showLegend && (
        <dl className="min-w-[130px] flex-1 space-y-2">
          {slices.map((slice) => (
            <div key={slice.key} className="flex items-center gap-2.5">
              <span
                aria-hidden
                className="size-2 shrink-0 rounded-[2px]"
                style={{ background: slice.color }}
              />
              <dt className="text-ink-muted text-xs">{slice.label}</dt>
              <dd className="numeric text-ink ml-auto text-sm">
                {slice.value}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

/** Horizontal severity bar used where a donut would be too heavy. */
export function SeverityBar({ counts }: { counts: SeverityCounts }) {
  const slices = CHARTED_SEVERITIES.map((severity: Severity) => ({
    key: severity,
    value: counts[severity],
    color: SEVERITY_CHART_COLOR[severity],
  })).filter((slice) => slice.value > 0);

  const total = slices.reduce((sum, slice) => sum + slice.value, 0);
  if (total === 0) {
    return <div className="bg-line h-1.5 w-full rounded-full" />;
  }

  return (
    <div className="bg-surface-raised flex h-1.5 w-full overflow-hidden rounded-full">
      {slices.map((slice) => (
        <span
          key={slice.key}
          style={{
            width: `${(slice.value / total) * 100}%`,
            background: slice.color,
          }}
        />
      ))}
    </div>
  );
}
