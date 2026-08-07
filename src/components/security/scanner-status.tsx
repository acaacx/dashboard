import { scannerLabel } from "@/domain/security/enums";
import type { ScannerHealth } from "@/domain/security/scan-run";
import { EmptyState } from "@/components/ui/panel";
import { relativeTime } from "@/lib/format";
import { HEALTH_TOKENS } from "./severity-tokens";

/**
 * Scanner Status.
 *
 * Sourced entirely from ScanRun records, never from findings: a scanner with
 * zero findings is healthy, a scanner that never ran is not, and only run
 * history can tell those apart.
 */
export function ScannerStatus({
  health,
  now,
}: {
  health: ScannerHealth[];
  now?: Date;
}) {
  if (health.length === 0) {
    return (
      <EmptyState
        title="No scanners have reported yet."
        hint="Scanner health appears once a pipeline posts results to /api/security/scans."
      />
    );
  }

  return (
    <ul className="divide-line divide-y">
      {health.map((entry) => {
        const tokens = HEALTH_TOKENS[entry.status];

        return (
          <li key={entry.scanner} className="py-2.5 first:pt-0 last:pb-0">
            {/* Two lines rather than two columns: this panel is narrow on the
                Overview grid, and a truncated scanner name is useless. */}
            <div className="flex items-baseline justify-between gap-3">
              <span className="flex min-w-0 items-baseline gap-2">
                <span
                  aria-hidden
                  className={`size-1.5 shrink-0 rounded-full ${tokens.dot}`}
                />
                <span className="text-ink text-sm whitespace-nowrap">
                  {scannerLabel(entry.scanner)}
                </span>
              </span>
              {entry.totalFindings !== undefined && (
                <span className="text-ink-faint shrink-0 font-mono text-[10px]">
                  {entry.totalFindings} reported
                </span>
              )}
            </div>

            <p className="mt-0.5 pl-3.5 text-xs">
              <span className={tokens.text}>{tokens.label}</span>
              <span className="text-ink-faint font-mono text-[11px]">
                {entry.lastScanAt
                  ? ` · ${relativeTime(entry.lastScanAt, now)}`
                  : " · never scanned"}
              </span>
            </p>

            {entry.status === "FAILED" && entry.error && (
              <p className="text-fail mt-0.5 pl-3.5 font-mono text-[10px] break-words">
                {entry.error}
              </p>
            )}
          </li>
        );
      })}
    </ul>
  );
}
