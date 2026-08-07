import { PageHeader } from "@/components/shell/page-header";
import { EmptyState, Panel } from "@/components/ui/panel";
import { relativeTime } from "@/lib/format";
import { getSecurityContainer } from "@/lib/security/container";
import type { PipelineStageView } from "@/lib/security/services/security-service";

/** Per-request: scan runs arrive continuously from CI. */
export const dynamic = "force-dynamic";

/**
 * Pipelines.
 *
 * Security stages are derived from ScanRun records per repository, so each
 * pipeline shows the scanners that actually ran for that repository rather than
 * a fixed four-stage template.
 *
 * Build, test, package and deploy stages are absent on purpose: they come from
 * the GitHub provider, which is not connected. Rendering placeholder stages
 * would put fictional deployment state on an operations dashboard.
 */
export default async function PipelinesPage() {
  const { securityService, platform } = await getSecurityContainer();
  const pipelines = await securityService.getRepositoryPipelines();

  return (
    <>
      <PageHeader
        title="Pipelines"
        subtitle="Security stages observed per repository, derived from scan runs."
      />

      {!platform.github.isConfigured() && (
        <p className="border-line bg-surface text-ink-faint mb-5 rounded-[var(--radius-panel)] border px-4 py-3 text-xs">
          Build, test, package and deploy stages appear once the GitHub provider
          is connected. Only stages backed by real scan runs are shown.
        </p>
      )}

      {pipelines.length === 0 ? (
        <Panel>
          <EmptyState title="No scan runs recorded yet." />
        </Panel>
      ) : (
        <div className="space-y-4">
          {pipelines.map((pipeline) => (
            <Panel
              key={pipeline.repositoryName}
              title={pipeline.repositoryName}
              eyebrow="Pipeline"
              description={
                pipeline.commitSha
                  ? `${pipeline.branch ?? "unknown branch"} · ${pipeline.commitSha.slice(0, 8)}`
                  : undefined
              }
              action={
                <span className="text-ink-faint font-mono text-[11px]">
                  {relativeTime(pipeline.lastRunAt)}
                </span>
              }
            >
              <ol className="flex flex-wrap items-stretch gap-2">
                {pipeline.stages.map((stage, index) => (
                  <li key={stage.scanner} className="flex items-stretch gap-2">
                    <Stage stage={stage} />
                    {index < pipeline.stages.length - 1 && (
                      <span
                        aria-hidden
                        className="text-ink-faint self-center font-mono text-xs"
                      >
                        →
                      </span>
                    )}
                  </li>
                ))}
              </ol>
            </Panel>
          ))}
        </div>
      )}
    </>
  );
}

const STAGE_TONE: Record<PipelineStageView["status"], string> = {
  PASSED: "border-ok/40 text-ok",
  FAILED: "border-fail/40 text-fail",
  RUNNING: "border-accent/40 text-accent",
};

function Stage({ stage }: { stage: PipelineStageView }) {
  return (
    <div
      className={`bg-surface-raised min-w-[130px] rounded border px-3 py-2.5 ${STAGE_TONE[stage.status]}`}
    >
      <p className="text-ink text-xs font-medium">{stage.name}</p>
      <p className="mt-1 font-mono text-[10px] tracking-wide uppercase">
        {stage.status === "PASSED"
          ? "Passed"
          : stage.status === "RUNNING"
            ? "Running"
            : `${stage.findings} finding${stage.findings === 1 ? "" : "s"}`}
      </p>
      {/* When the scan ran. Scanner output does not report its own duration,
          so none is shown rather than displaying ingestion cost as if it were. */}
      <p className="text-ink-faint mt-1 font-mono text-[10px]">
        {relativeTime(stage.lastRunAt)}
      </p>
    </div>
  );
}
