"use client";

import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { scannerLabel } from "@/domain/security/enums";
import { EmptyState } from "@/components/ui/panel";
import { categoricalColor } from "./severity-tokens";
import { SimpleTooltip } from "./chart-tooltip";

/**
 * Findings by scanner.
 *
 * The data is a plain `Record<string, number>` from the statistics service, so
 * a scanner this UI has never heard of renders correctly the moment it reports
 * findings — no enumeration of known scanners lives here.
 */
export function ScannerChart({ byScanner }: { byScanner: Record<string, number> }) {
  const data = Object.entries(byScanner)
    .map(([scanner, value], index) => ({
      key: scanner,
      label: scannerLabel(scanner),
      value,
      color: categoricalColor(index),
    }))
    .sort((a, b) => b.value - a.value);

  if (data.length === 0) {
    return <EmptyState title="No open findings to break down by scanner." />;
  }

  return (
    <div style={{ height: Math.max(140, data.length * 38) }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 0, right: 12, bottom: 0, left: 0 }}
          barCategoryGap={10}
        >
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="label"
            width={78}
            axisLine={false}
            tickLine={false}
            tick={{
              fill: "var(--color-ink-muted)",
              fontSize: 11,
              fontFamily: "var(--font-mono)",
            }}
          />
          <Tooltip
            content={<SimpleTooltip />}
            cursor={{ fill: "var(--color-surface-hover)" }}
          />
          <Bar dataKey="value" radius={[0, 3, 3, 0]} isAnimationActive={false}>
            {data.map((entry) => (
              <Cell key={entry.key} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
