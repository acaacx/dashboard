import Link from "next/link";

import { scannerLabel } from "@/domain/security/enums";
import { PageHeader } from "@/components/shell/page-header";
import { SeverityBar } from "@/components/security/severity-chart";
import { EmptyState, Panel } from "@/components/ui/panel";
import { requireUser } from "@/lib/auth/guards";
import { relativeTime } from "@/lib/format";
import { getSecurityContainer } from "@/lib/security/container";

/** Per-request: findings change as pipelines report. */
export const dynamic = "force-dynamic";

/**
 * Applications / repository security view.
 *
 * Per-repository roll-up of open findings and scanner outcomes. Built from the
 * same normalized findings and scan runs as every other page — no separate
 * data path, no second source of truth.
 */
export default async function ApplicationsPage() {
  // Layouts do not re-run on every client-side navigation, so the layout check
  // is a redirect rather than a gate. This is the gate.
  await requireUser();

  const { securityService, platform } = await getSecurityContainer();
  const summaries = await securityService.getRepositorySummaries();

  const githubConnected = platform.github.isConfigured();

  return (
    <>
      <PageHeader
        title="Applications"
        subtitle="Security posture per repository, rolled up from normalized findings."
      />

      {!githubConnected && (
        <p className="border-line bg-surface text-ink-faint mb-5 rounded-[var(--radius-panel)] border px-4 py-3 text-xs">
          The GitHub provider is not connected, so ownership, default branches
          and deployment history are unavailable. Everything below is derived
          from scan results alone.
        </p>
      )}

      {summaries.length === 0 ? (
        <Panel>
          <EmptyState title="No repositories have reported findings yet." />
        </Panel>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {summaries.map((summary) => (
            <Panel
              key={summary.repositoryName}
              title={summary.repositoryName}
              eyebrow="Repository"
              action={
                <Link
                  href={`/dashboard/security?repository=${encodeURIComponent(summary.repositoryName)}`}
                  className="text-accent font-mono text-[11px] hover:underline"
                >
                  View findings →
                </Link>
              }
            >
              <div className="mb-4 flex items-baseline gap-2">
                <span className="numeric text-ink text-2xl leading-none font-medium">
                  {summary.openFindings}
                </span>
                <span className="text-ink-muted text-sm">open findings</span>
              </div>

              <SeverityBar counts={summary.bySeverity} />

              <dl className="mt-3 grid grid-cols-4 gap-2">
                <Count label="Critical" value={summary.bySeverity.CRITICAL} tone="text-critical" />
                <Count label="High" value={summary.bySeverity.HIGH} tone="text-high" />
                <Count label="Medium" value={summary.bySeverity.MEDIUM} tone="text-medium" />
                <Count label="Low" value={summary.bySeverity.LOW} tone="text-low" />
              </dl>

              <div className="border-line mt-4 border-t pt-3">
                <p className="text-ink-faint mb-2 font-mono text-[10px] tracking-[0.14em] uppercase">
                  Scanners
                </p>
                <ul className="space-y-1.5">
                  {summary.scanners.map((entry) => (
                    <li
                      key={entry.scanner}
                      className="flex items-center justify-between gap-3 text-xs"
                    >
                      <span className="text-ink-muted font-mono">
                        {scannerLabel(entry.scanner)}
                      </span>
                      <span className="flex items-center gap-2">
                        {entry.lastScanAt && (
                          <span className="text-ink-faint font-mono text-[10px]">
                            {relativeTime(entry.lastScanAt)}
                          </span>
                        )}
                        <span
                          className={`font-mono text-[10px] uppercase ${
                            entry.status === "PASSED"
                              ? "text-ok"
                              : entry.status === "FAILED"
                                ? "text-fail"
                                : "text-ink-faint"
                          }`}
                        >
                          {entry.status === "PASSED"
                            ? "Passed"
                            : entry.status === "FAILED"
                              ? `Failed (${entry.openFindings})`
                              : "Never run"}
                        </span>
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </Panel>
          ))}
        </div>
      )}
    </>
  );
}

function Count({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: string;
}) {
  return (
    <div>
      <dt className="text-ink-faint font-mono text-[10px] uppercase">{label}</dt>
      <dd className={`numeric mt-0.5 text-sm ${tone}`}>{value}</dd>
    </div>
  );
}
