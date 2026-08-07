"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { TrendPoint } from "@/domain/security/finding";
import { EmptyState } from "@/components/ui/panel";
import { SimpleTooltip } from "./chart-tooltip";

/**
 * Findings trend: open backlog as an area, with new and resolved as lines.
 *
 * Every point is computed by the repository from stored lifecycle timestamps —
 * this component performs no date arithmetic, which is why the chart and the
 * summary cards can never disagree.
 */
export function FindingsTrend({
  points,
  height = 220,
}: {
  points: TrendPoint[];
  height?: number;
}) {
  if (points.length === 0) {
    return <EmptyState title="Not enough history to plot a trend yet." />;
  }

  const data = points.map((point) => ({
    ...point,
    // Short axis label; the tooltip carries the full date.
    day: point.date.slice(5),
  }));

  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={data}
          margin={{ top: 8, right: 8, bottom: 0, left: -18 }}
        >
          <defs>
            <linearGradient id="openFill" x1="0" y1="0" x2="0" y2="1">
              <stop
                offset="0%"
                stopColor="var(--color-accent)"
                stopOpacity={0.28}
              />
              <stop
                offset="100%"
                stopColor="var(--color-accent)"
                stopOpacity={0}
              />
            </linearGradient>
          </defs>

          <CartesianGrid
            stroke="var(--color-line)"
            strokeDasharray="2 4"
            vertical={false}
          />
          <XAxis
            dataKey="day"
            axisLine={false}
            tickLine={false}
            minTickGap={24}
            tick={{
              fill: "var(--color-ink-faint)",
              fontSize: 10,
              fontFamily: "var(--font-mono)",
            }}
          />
          <YAxis
            axisLine={false}
            tickLine={false}
            width={44}
            allowDecimals={false}
            tick={{
              fill: "var(--color-ink-faint)",
              fontSize: 10,
              fontFamily: "var(--font-mono)",
            }}
          />
          <Tooltip
            content={<SimpleTooltip />}
            cursor={{ stroke: "var(--color-line-strong)" }}
          />

          <Area
            type="monotone"
            dataKey="open"
            name="Open"
            stroke="var(--color-accent)"
            strokeWidth={1.75}
            fill="url(#openFill)"
            isAnimationActive={false}
            dot={false}
          />
          <Line
            type="monotone"
            dataKey="new"
            name="New"
            stroke="var(--color-high)"
            strokeWidth={1.5}
            dot={false}
            isAnimationActive={false}
          />
          <Line
            type="monotone"
            dataKey="resolved"
            name="Resolved"
            stroke="var(--color-ok)"
            strokeWidth={1.5}
            strokeDasharray="3 3"
            dot={false}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>

      <ul className="text-ink-muted mt-2 flex flex-wrap gap-4 text-xs">
        <LegendItem color="var(--color-accent)" label="Open" />
        <LegendItem color="var(--color-high)" label="New" />
        <LegendItem color="var(--color-ok)" label="Resolved" dashed />
      </ul>
    </div>
  );
}

function LegendItem({
  color,
  label,
  dashed = false,
}: {
  color: string;
  label: string;
  dashed?: boolean;
}) {
  return (
    <li className="flex items-center gap-1.5">
      <span
        aria-hidden
        className="inline-block h-0.5 w-4"
        style={
          dashed
            ? {
                backgroundImage: `repeating-linear-gradient(to right, ${color} 0 3px, transparent 3px 6px)`,
              }
            : { background: color }
        }
      />
      {label}
    </li>
  );
}
