import { PageHeader } from "@/components/shell/page-header";
import { FindingsTrend } from "@/components/security/findings-trend";
import { ScannerStatus } from "@/components/security/scanner-status";
import { SecurityFindingsCard } from "@/components/security/security-findings-card";
import { TopVulnerabilities } from "@/components/security/top-vulnerabilities";
import { Panel } from "@/components/ui/panel";
import { Stat } from "@/components/ui/stat";
import { requireUser } from "@/lib/auth/guards";
import { formatDuration } from "@/lib/format";
import { getSecurityService } from "@/lib/security/container";

/**
 * Findings change whenever a pipeline posts results, so this page must be
 * rendered per request. Without this it would be prerendered at build time and
 * would keep serving the build-time snapshot forever.
 */
export const dynamic = "force-dynamic";

/**
 * Overview.
 *
 * Every number here comes from the normalized security service. There is no
 * hardcoded count anywhere on this page, and no component receives scanner
 * output — only domain objects.
 */
export default async function OverviewPage() {
  // Layouts do not re-run on every client-side navigation, so the layout check
  // is a redirect rather than a gate. This is the gate.
  await requireUser();

  const service = await getSecurityService();
  const overview = await service.getOverview("all");
  const { statistics, topFindings, scannerHealth, trend } = overview;

  const healthy = scannerHealth.filter(
    (entry) => entry.status === "HEALTHY",
  ).length;

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="Security and delivery posture across all monitored repositories."
      />

      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat
          label="Open findings"
          value={statistics.totalOpen}
          hint={`${statistics.total} tracked in total`}
        />
        <Stat
          label="Critical"
          value={statistics.bySeverity.CRITICAL}
          tone="text-critical"
          hint={`${statistics.bySeverity.HIGH} high severity`}
        />
        <Stat
          label="Scanners healthy"
          value={`${healthy}/${scannerHealth.length}`}
          tone={healthy === scannerHealth.length ? "text-ok" : "text-warn"}
          hint="Derived from scan runs"
        />
        <Stat
          label="Mean time to remediate"
          value={formatDuration(statistics.meanTimeToRemediateHours)}
          hint={`${statistics.resolvedFindings} resolved`}
        />
      </div>

      <div className="mb-5 grid grid-cols-1 gap-5 lg:grid-cols-12">
        <div className="lg:col-span-4">
          <SecurityFindingsCard initialStatistics={statistics} />
        </div>

        <div className="lg:col-span-5">
          <Panel
            title="Top Vulnerabilities"
            eyebrow="Highest severity, most recent"
            className="h-full"
          >
            <TopVulnerabilities findings={topFindings} />
          </Panel>
        </div>

        <div className="lg:col-span-3">
          <Panel title="Scanner Status" eyebrow="Pipeline health" className="h-full">
            <ScannerStatus health={scannerHealth} />
          </Panel>
        </div>
      </div>

      <Panel
        title="Findings Trend"
        eyebrow="Last 14 days"
        description="Open backlog against findings created and resolved each day."
      >
        <FindingsTrend points={trend} height={200} />
      </Panel>
    </>
  );
}
