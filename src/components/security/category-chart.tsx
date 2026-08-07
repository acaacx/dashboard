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

import { categoryLabel } from "@/domain/security/enums";
import { EmptyState } from "@/components/ui/panel";
import { categoricalColor } from "./severity-tokens";
import { SimpleTooltip } from "./chart-tooltip";

/**
 * Findings by category (SAST / SCA / SECRET / IAC / CONTAINER / …).
 *
 * Category is a normalized domain value assigned by the adapter, which is why
 * a Trivy report can contribute to three different bars here without this
 * component knowing Trivy exists.
 */
export function CategoryChart({
  byCategory,
}: {
  byCategory: Record<string, number>;
}) {
  const data = Object.entries(byCategory)
    .map(([category, value], index) => ({
      key: category,
      label: categoryLabel(category),
      value,
      // Offset the palette so category bars are not the same hues as the
      // scanner chart sitting next to them.
      color: categoricalColor(index + 2),
    }))
    .sort((a, b) => b.value - a.value);

  if (data.length === 0) {
    return <EmptyState title="No open findings to break down by category." />;
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
