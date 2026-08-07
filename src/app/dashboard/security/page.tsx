import { PageHeader } from "@/components/shell/page-header";
import { CategoryChart } from "@/components/security/category-chart";
import {
  DEFAULT_QUERY_STATE,
  FindingsTable,
} from "@/components/security/findings-table";
import { FindingsTrend } from "@/components/security/findings-trend";
import { ScannerChart } from "@/components/security/scanner-chart";
import { ScannerStatus } from "@/components/security/scanner-status";
import { SeverityDonut } from "@/components/security/severity-chart";
import { Panel } from "@/components/ui/panel";
import { Stat } from "@/components/ui/stat";
import { formatDuration } from "@/lib/format";
import { getSecurityService } from "@/lib/security/container";

/** Per-request: findings change as pipelines report. */
export const dynamic = "force-dynamic";

/**
 * Security findings page.
 *
 * Rendered on the server with the first page of results already resolved, then
 * handed to the client table which re-queries the API as filters change. The
 * initial paint is real data, not a spinner.
 */
export default async function SecurityPage({
  searchParams,
}: PageProps<"/dashboard/security">) {
  const params = await searchParams;
  const selectedId = typeof params.finding === "string" ? params.finding : undefined;

  const service = await getSecurityService();

  const [statistics, trend, scannerHealth, filterOptions, firstPage] =
    await Promise.all([
      service.getStatistics(),
      service.getTrend(30),
      service.getScannerHealth(),
      service.getFilterOptions(),
      service.getFindings({
        status: DEFAULT_QUERY_STATE.status,
        sortBy: DEFAULT_QUERY_STATE.sortBy,
        sortDirection: DEFAULT_QUERY_STATE.sortDirection,
        page: 1,
        pageSize: 25,
      }),
    ]);

  // Deep link from the Overview's Top Vulnerabilities list opens the drawer.
  const selectedFinding = selectedId
    ? await service.getFindingById(selectedId)
    : null;

  return (
    <>
      <PageHeader
        title="Security"
        subtitle="Normalized findings from every connected scanner."
      />

      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Total open" value={statistics.totalOpen} />
        <Stat
          label="Critical"
          value={statistics.bySeverity.CRITICAL}
          tone="text-critical"
        />
        <Stat label="High" value={statistics.bySeverity.HIGH} tone="text-high" />
        <Stat
          label="Medium"
          value={statistics.bySeverity.MEDIUM}
          tone="text-medium"
        />
        <Stat
          label="Resolved"
          value={statistics.totalResolved}
          tone="text-ok"
          hint={formatDuration(statistics.meanTimeToRemediateHours) + " mean"}
        />
        <Stat
          label="Accepted risk"
          value={statistics.totalAcceptedRisk}
          tone="text-medium"
        />
      </div>

      <div className="mb-5 grid grid-cols-1 gap-5 lg:grid-cols-12">
        <div className="lg:col-span-3">
          <Panel title="Findings by Severity" className="h-full">
            <SeverityDonut counts={statistics.bySeverity} size={148} />
          </Panel>
        </div>
        <div className="lg:col-span-3">
          <Panel title="Findings by Scanner" className="h-full">
            <ScannerChart byScanner={statistics.byScanner} />
          </Panel>
        </div>
        <div className="lg:col-span-3">
          <Panel title="Findings by Category" className="h-full">
            <CategoryChart byCategory={statistics.byCategory} />
          </Panel>
        </div>
        <div className="lg:col-span-3">
          <Panel title="Scanner Status" className="h-full">
            <ScannerStatus health={scannerHealth} />
          </Panel>
        </div>
      </div>

      <div className="mb-5">
        <Panel
          title="Findings Trend"
          eyebrow="Last 30 days"
          description="Are findings accumulating faster than they are being fixed?"
        >
          <FindingsTrend points={trend} />
        </Panel>
      </div>

      <Panel title="All Findings" eyebrow="Searchable · filterable" flush>
        <FindingsTable
          initialResult={firstPage}
          filterOptions={filterOptions}
          initialSelected={selectedFinding}
        />
      </Panel>
    </>
  );
}
