import Link from "next/link";

import type { SecurityFinding } from "@/domain/security/finding";
import { EmptyState } from "@/components/ui/panel";
import { ScannerBadge, SeverityBadge } from "@/components/ui/badge";

/**
 * Top Vulnerabilities.
 *
 * Shows finding, repository/resource, scanner and severity, exactly as the
 * normalized model provides them. Ordering comes from the service (severity,
 * then recency) rather than from a sort in this file.
 */
export function TopVulnerabilities({
  findings,
}: {
  findings: SecurityFinding[];
}) {
  if (findings.length === 0) {
    return <EmptyState title="No open findings." />;
  }

  return (
    <ul className="divide-line divide-y">
      {findings.map((finding) => (
        <li key={finding.id}>
          <Link
            href={`/dashboard/security?finding=${encodeURIComponent(finding.id)}`}
            className="hover:bg-surface-hover -mx-2 flex items-start justify-between gap-4 rounded px-2 py-3 transition-colors"
          >
            <div className="min-w-0">
              <p className="text-ink truncate text-sm">{finding.title}</p>
              <p className="text-ink-faint mt-1 truncate font-mono text-[11px]">
                {finding.repositoryName ?? finding.resource ?? "unassigned"}
                {finding.cve ? ` · ${finding.cve}` : ""}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <ScannerBadge scanner={finding.scanner} />
              <SeverityBadge severity={finding.severity} />
            </div>
          </Link>
        </li>
      ))}
    </ul>
  );
}
