"use client";

import { useCallback, useEffect, useState } from "react";

import type { FindingStatistics } from "@/domain/security/finding";
import { Panel } from "@/components/ui/panel";
import type { Timeframe } from "@/lib/security/services/security-service";
import { SeverityDonut } from "./severity-chart";

const TIMEFRAMES: Array<{ value: Timeframe; label: string }> = [
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
  { value: "30d", label: "30d" },
  { value: "all", label: "All" },
];

/**
 * The Overview "Security Findings" card.
 *
 * Server-rendered with real statistics, then re-fetches from
 * /api/security/statistics when the timeframe changes. Values are never
 * computed here — the card asks the API and draws the answer, so the donut, the
 * Security page and the API can never drift apart.
 */
export function SecurityFindingsCard({
  initialStatistics,
  initialTimeframe = "all",
}: {
  initialStatistics: FindingStatistics;
  initialTimeframe?: Timeframe;
}) {
  const [timeframe, setTimeframe] = useState<Timeframe>(initialTimeframe);

  // Results are cached per timeframe and the rendered value is derived from
  // that cache, so switching back to an already-loaded timeframe is instant and
  // no state is written synchronously during an effect.
  const [cache, setCache] = useState<Partial<Record<Timeframe, FindingStatistics>>>(
    () => ({ [initialTimeframe]: initialStatistics }),
  );
  const [failedTimeframe, setFailedTimeframe] = useState<Timeframe | null>(null);

  const statistics = cache[timeframe] ?? initialStatistics;
  const error = failedTimeframe === timeframe;
  const loading = cache[timeframe] === undefined && !error;

  const load = useCallback(async (next: Timeframe) => {
    const response = await fetch(`/api/security/statistics?timeframe=${next}`, {
      headers: { accept: "application/json" },
    });
    if (!response.ok) throw new Error(`Request failed (${response.status})`);
    const body = (await response.json()) as { statistics: FindingStatistics };
    return body.statistics;
  }, []);

  useEffect(() => {
    if (cache[timeframe] !== undefined) return;

    let cancelled = false;
    load(timeframe)
      .then((next) => {
        if (!cancelled) setCache((current) => ({ ...current, [timeframe]: next }));
      })
      .catch(() => {
        if (!cancelled) setFailedTimeframe(timeframe);
      });

    return () => {
      cancelled = true;
    };
  }, [timeframe, cache, load]);

  return (
    <Panel
      title="Security Findings"
      eyebrow="Normalized across scanners"
      action={
        <div
          role="group"
          aria-label="Timeframe"
          className="border-line bg-surface-raised flex rounded border p-0.5"
        >
          {TIMEFRAMES.map((option) => (
            <button
              key={option.value}
              type="button"
              onClick={() => setTimeframe(option.value)}
              aria-pressed={timeframe === option.value}
              className={`rounded px-2 py-1 font-mono text-[10px] tracking-wide uppercase transition-colors ${
                timeframe === option.value
                  ? "bg-accent/15 text-accent"
                  : "text-ink-faint hover:text-ink-muted"
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
      }
    >
      <div
        className={`transition-opacity ${loading ? "opacity-60" : "opacity-100"}`}
      >
        <div className="mb-4 flex items-baseline gap-2">
          <span className="numeric text-ink text-3xl leading-none font-medium">
            {statistics.totalOpen}
          </span>
          <span className="text-ink-muted text-sm">Total open</span>
        </div>

        <SeverityDonut counts={statistics.bySeverity} />

        {/* Additional context, kept to one compact row so the card stays calm. */}
        <dl className="border-line mt-5 grid grid-cols-3 gap-3 border-t pt-4">
          <MiniStat label="New" value={statistics.newFindings} />
          <MiniStat label="Resolved" value={statistics.resolvedFindings} />
          <MiniStat label="Accepted" value={statistics.totalAcceptedRisk} />
        </dl>

        {error && (
          <p className="text-fail mt-3 text-xs" role="status">
            Could not load statistics for this timeframe.
          </p>
        )}
      </div>
    </Panel>
  );
}

function MiniStat({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <dt className="text-ink-faint font-mono text-[10px] tracking-[0.12em] uppercase">
        {label}
      </dt>
      <dd className="numeric text-ink mt-1 text-lg leading-none">{value}</dd>
    </div>
  );
}
