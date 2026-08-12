"use client";

import { useEffect, useRef, useState } from "react";

import type { FindingDecision } from "@/domain/security/decision";
import {
  categoryLabel,
  scannerLabel,
  statusLabel,
  type FindingStatus,
} from "@/domain/security/enums";
import type { SecurityFinding } from "@/domain/security/finding";
import { ScannerBadge, SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { formatDateTime } from "@/lib/format";
import {
  MAX_STATUS_REASON_LENGTH,
  selectableTransitions,
  type SetFindingStatusAction,
} from "@/lib/security/status-change";

/**
 * Finding detail drawer.
 *
 * XSS posture: every scanner-supplied string here — title, description,
 * remediation, metadata values — is rendered as text through JSX, which escapes
 * it. There is no `dangerouslySetInnerHTML` anywhere in this codebase, and
 * scanner output must never be rendered as HTML or markdown without an explicit
 * sanitiser. `sourceUrl` is additionally scheme-checked before it becomes a
 * link, so a `javascript:` URL in a malicious rule definition cannot execute.
 */
export function FindingDetails({
  finding,
  onClose,
  onApplyStatus,
  onStatusChanged,
  canDecide = false,
  loadHistory,
}: {
  finding: SecurityFinding;
  onClose: () => void;
  /** Absent in read-only contexts; the decision form is then not rendered. */
  onApplyStatus?: SetFindingStatusAction;
  onStatusChanged?: (finding: SecurityFinding) => void;
  /**
   * Whether the signed-in user may decide. Defaults to `false`: this component
   * cannot know who is looking, so a caller that did not ask the guard gets the
   * locked control. The action re-checks regardless.
   */
  canDecide?: boolean;
  /**
   * Loads the decision trail for this finding. Injected like `onApplyStatus`
   * so the component stays fetch-free and tests await the injected call.
   * Absent ⇒ no timeline at all, failing closed like `canDecide`.
   */
  loadHistory?: (id: string) => Promise<FindingDecision[]>;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);

  const [history, setHistory] = useState<
    | { kind: "loading" }
    | { kind: "error" }
    | { kind: "loaded"; decisions: FindingDecision[] }
  >({ kind: "loading" });

  // No synchronous "loading" reset here: the initial state covers the first
  // render, and on a refetch the previous timeline stays visible until the
  // fresh one arrives, rather than flashing a loading line.
  useEffect(() => {
    if (!loadHistory) return;
    let cancelled = false;
    loadHistory(finding.id).then(
      (decisions) => {
        if (!cancelled) setHistory({ kind: "loaded", decisions });
      },
      () => {
        // The audit view is not a gate: the drawer and the decision form stay
        // usable when history cannot load.
        if (!cancelled) setHistory({ kind: "error" });
      },
    );
    return () => {
      cancelled = true;
    };
    // statusChangedAt re-runs the fetch after a successful decision, so the
    // timeline shows what was stored rather than an optimistic guess.
  }, [loadHistory, finding.id, finding.statusChangedAt]);

  useEffect(() => {
    closeRef.current?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const safeSourceUrl = toSafeHttpUrl(finding.sourceUrl);

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <button
        type="button"
        aria-label="Close details"
        onClick={onClose}
        className="absolute inset-0 bg-black/60"
      />

      <aside
        role="dialog"
        aria-modal="true"
        aria-label={`Finding details: ${finding.title}`}
        className="border-line bg-surface relative flex h-full w-full max-w-xl flex-col overflow-y-auto border-l shadow-2xl"
      >
        <header className="border-line bg-surface sticky top-0 z-10 border-b px-5 py-4">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <StatusBadge status={finding.status} />
                <ScannerBadge scanner={finding.scanner} />
                <span className="border-line text-ink-faint inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase">
                  {categoryLabel(finding.category)}
                </span>
              </div>
              <h2 className="text-ink text-sm leading-snug font-semibold">
                {finding.title}
              </h2>
            </div>
            <button
              ref={closeRef}
              type="button"
              onClick={onClose}
              className="border-line text-ink-muted hover:text-ink hover:border-line-strong shrink-0 rounded border px-2 py-1 font-mono text-[11px]"
            >
              Esc
            </button>
          </div>
        </header>

        <div className="space-y-6 px-5 py-5">
          {finding.description && (
            <Section title="Description">
              <p className="text-ink-muted text-sm leading-relaxed break-words whitespace-pre-wrap">
                {finding.description}
              </p>
            </Section>
          )}

          <Section title="Location">
            <Fields>
              <Field label="Repository" value={finding.repositoryName} mono />
              <Field label="Branch" value={finding.branch} mono />
              <Field label="Commit" value={finding.commitSha?.slice(0, 12)} mono />
              <Field label="File" value={finding.file} mono />
              <Field
                label="Line"
                value={
                  finding.startLine
                    ? finding.endLine && finding.endLine !== finding.startLine
                      ? `${finding.startLine}–${finding.endLine}`
                      : String(finding.startLine)
                    : undefined
                }
                mono
              />
              <Field label="Resource" value={finding.resource} mono />
            </Fields>
          </Section>

          {(finding.cve ||
            finding.cwe ||
            finding.packageName ||
            finding.ruleId) && (
            <Section title="Classification">
              <Fields>
                <Field label="CVE" value={finding.cve} mono />
                <Field label="CWE" value={finding.cwe} mono />
                <Field label="Rule ID" value={finding.ruleId} mono />
                <Field label="Package" value={finding.packageName} mono />
                <Field
                  label="Installed version"
                  value={finding.packageVersion}
                  mono
                />
                <Field
                  label="Fixed version"
                  value={finding.fixedVersion}
                  mono
                  tone={finding.fixedVersion ? "text-ok" : undefined}
                />
              </Fields>
            </Section>
          )}

          {(finding.azureResourceId ||
            finding.resourceGroup ||
            finding.subscriptionId ||
            finding.environment ||
            finding.applicationId) && (
            <Section title="Inventory">
              <Fields>
                <Field label="Application" value={finding.applicationId} mono />
                <Field label="Environment" value={finding.environment} mono />
                <Field
                  label="Azure resource"
                  value={finding.azureResourceId}
                  mono
                />
                <Field label="Resource group" value={finding.resourceGroup} mono />
                <Field label="Subscription" value={finding.subscriptionId} mono />
              </Fields>
            </Section>
          )}

          <Section title="Lifecycle">
            <Fields>
              <Field
                label="First detected"
                value={formatDateTime(finding.firstDetectedAt)}
              />
              <Field
                label="Last detected"
                value={formatDateTime(finding.lastDetectedAt)}
              />
              <Field
                label="Resolved"
                value={
                  finding.resolvedAt
                    ? formatDateTime(finding.resolvedAt)
                    : undefined
                }
              />
              <Field label="Fingerprint" value={finding.fingerprint} mono truncate />
            </Fields>
          </Section>

          {(finding.statusReason || onApplyStatus) && (
            <Section title="Decision">
              {finding.statusReason && (
                <div className="border-line bg-surface-raised mb-4 rounded border px-3 py-2.5">
                  <p className="text-ink-muted text-sm leading-relaxed break-words whitespace-pre-wrap">
                    {finding.statusReason}
                  </p>
                  {(finding.statusChangedAt || finding.statusChangedBy) && (
                    <p className="text-ink-faint mt-1.5 font-mono text-[10px]">
                      {statusLabel(finding.status)}
                      {finding.statusChangedAt &&
                        ` · ${formatDateTime(finding.statusChangedAt)}`}
                      {finding.statusChangedBy &&
                        ` · ${finding.statusChangedBy}`}
                    </p>
                  )}
                </div>
              )}

              {onApplyStatus && (
                <DecisionForm
                  finding={finding}
                  onApplyStatus={onApplyStatus}
                  onStatusChanged={onStatusChanged}
                  locked={!canDecide}
                />
              )}
            </Section>
          )}

          {loadHistory && (
            <Section title="Decision history">
              {history.kind === "loading" ? (
                <p className="text-ink-faint text-sm">
                  Loading decision history…
                </p>
              ) : history.kind === "error" ? (
                <p className="text-ink-faint text-sm">
                  Decision history could not be loaded.
                </p>
              ) : history.decisions.length === 0 ? (
                /* The no-backfill decision, visible: findings decided before
                   history shipped have a status but no recorded trail. */
                <p className="text-ink-faint text-sm">
                  Earlier decisions were not recorded.
                </p>
              ) : (
                <ol className="divide-line divide-y">
                  {history.decisions.map((decision) => (
                    <li key={decision.id} className="py-2">
                      <p className="text-ink text-xs">
                        <span className="font-mono">{decision.decidedBy}</span>{" "}
                        moved{" "}
                        <span className="font-mono">{decision.fromStatus}</span>{" "}
                        →{" "}
                        <span className="font-mono">{decision.toStatus}</span>
                      </p>
                      <p className="text-ink-faint mt-0.5 font-mono text-[10px]">
                        {formatDateTime(decision.decidedAt)}
                      </p>
                      {decision.reason && (
                        <p className="text-ink-muted mt-1 text-sm leading-relaxed break-words whitespace-pre-wrap">
                          {decision.reason}
                        </p>
                      )}
                    </li>
                  ))}
                </ol>
              )}
            </Section>
          )}

          <Section title="Remediation">
            {finding.remediation ? (
              <p className="text-ink-muted text-sm leading-relaxed break-words whitespace-pre-wrap">
                {finding.remediation}
              </p>
            ) : (
              /* Never invent guidance the scanner did not provide. */
              <p className="text-ink-faint text-sm">
                {scannerLabel(finding.scanner)} did not provide remediation
                guidance for this finding.
              </p>
            )}
            {safeSourceUrl && (
              <a
                href={safeSourceUrl}
                target="_blank"
                rel="noreferrer noopener"
                className="text-accent mt-3 inline-block font-mono text-xs hover:underline"
              >
                View scanner reference ↗
              </a>
            )}
          </Section>

          {finding.metadata && Object.keys(finding.metadata).length > 0 && (
            <Section title="Scanner metadata">
              <dl className="divide-line divide-y">
                {Object.entries(finding.metadata).map(([key, value]) => (
                  <div
                    key={key}
                    className="grid grid-cols-[minmax(0,140px)_1fr] gap-3 py-1.5"
                  >
                    <dt className="text-ink-faint truncate font-mono text-[11px]">
                      {key}
                    </dt>
                    <dd className="text-ink-muted font-mono text-[11px] break-words">
                      {renderMetadataValue(value)}
                    </dd>
                  </div>
                ))}
              </dl>
            </Section>
          )}
        </div>
      </aside>
    </div>
  );
}

/**
 * Manual status change.
 *
 * The option list comes from `selectableTransitions`, which withholds manual
 * RESOLVED. That is UI policy, and the Server Action enforces it again — this
 * select is not a security boundary.
 *
 * `statusReason` is free text a person wrote. It is rendered as JSX text like
 * every other string in this drawer; there is no `dangerouslySetInnerHTML`
 * anywhere in this codebase.
 */
function DecisionForm({
  finding,
  onApplyStatus,
  onStatusChanged,
  locked,
}: {
  finding: SecurityFinding;
  onApplyStatus: SetFindingStatusAction;
  onStatusChanged?: (finding: SecurityFinding) => void;
  /** A viewer sees the control it cannot use, and the reason, rather than nothing. */
  locked: boolean;
}) {
  const targets = selectableTransitions(finding.status);
  const [target, setTarget] = useState<FindingStatus | "">("");
  const [reason, setReason] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<
    { code: string; message: string } | undefined
  >();

  // Defensive: every current status yields at least one target today. This
  // guards a future edit to ALLOWED_MANUAL_TRANSITIONS.
  if (targets.length === 0) return null;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (locked || !target || pending) return;

    setPending(true);
    setError(undefined);

    const result = await onApplyStatus(
      finding.id,
      target,
      reason.trim() === "" ? undefined : reason,
    );

    setPending(false);

    if (!result.ok) {
      setError({ code: result.code, message: result.message });
      return;
    }

    setReason("");
    setTarget("");
    onStatusChanged?.(result.finding);
  };

  return (
    <form onSubmit={submit} className="space-y-2.5">
      <label className="block">
        <span className="text-ink-faint mb-1 block font-mono text-[10px] tracking-[0.14em] uppercase">
          Change status to
        </span>
        <select
          value={target}
          disabled={pending || locked}
          onChange={(event) =>
            setTarget(event.target.value as FindingStatus | "")
          }
          className="border-line bg-surface-raised text-ink focus:border-accent/50 w-full rounded border px-2 py-1.5 font-mono text-[11px] outline-none disabled:opacity-50"
        >
          <option value="">Select a status…</option>
          {targets.map((status) => (
            <option key={status} value={status}>
              {statusLabel(status)}
            </option>
          ))}
        </select>
      </label>

      <label className="block">
        <span className="text-ink-faint mb-1 block font-mono text-[10px] tracking-[0.14em] uppercase">
          Reason
        </span>
        <textarea
          value={reason}
          rows={3}
          maxLength={MAX_STATUS_REASON_LENGTH}
          disabled={pending || locked}
          onChange={(event) => setReason(event.target.value)}
          placeholder="Why is this the right call? Required unless reopening."
          className="border-line bg-surface-raised text-ink placeholder:text-ink-faint focus:border-accent/50 w-full resize-y rounded border px-2 py-1.5 text-sm outline-none disabled:opacity-50"
        />
      </label>

      {locked && (
        <p className="text-ink-faint text-xs leading-relaxed">
          Approver role is required to change a finding&rsquo;s status. Every
          justification already recorded is visible above.
        </p>
      )}

      {error && (
        <p role="alert" className="text-fail text-xs">
          {error.message}{" "}
          {error.code === "UNAUTHENTICATED" && (
            /* A full document load, not a next/link: an expired session needs
               the server to redirect and set a fresh cookie. */
            <a href="/login" className="text-accent underline">
              Sign in
            </a>
          )}
        </p>
      )}

      <button
        type="submit"
        disabled={pending || locked || target === ""}
        className="border-line text-ink-muted hover:border-line-strong hover:text-ink rounded border px-2.5 py-1 font-mono text-[11px] transition-colors disabled:cursor-not-allowed disabled:opacity-40"
      >
        {pending ? "Applying…" : "Apply"}
      </button>
    </form>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      <h3 className="text-ink-faint mb-2.5 font-mono text-[10px] font-medium tracking-[0.14em] uppercase">
        {title}
      </h3>
      {children}
    </section>
  );
}

function Fields({ children }: { children: React.ReactNode }) {
  return <dl className="divide-line divide-y">{children}</dl>;
}

function Field({
  label,
  value,
  mono = false,
  truncate = false,
  tone,
}: {
  label: string;
  value?: string;
  mono?: boolean;
  truncate?: boolean;
  tone?: string;
}) {
  if (!value) return null;
  return (
    <div className="grid grid-cols-[minmax(0,140px)_1fr] gap-3 py-1.5">
      <dt className="text-ink-faint text-xs">{label}</dt>
      <dd
        className={`text-xs ${tone ?? "text-ink"} ${
          mono ? "font-mono" : ""
        } ${truncate ? "truncate" : "break-words"}`}
        title={truncate ? value : undefined}
      >
        {value}
      </dd>
    </div>
  );
}

/** Metadata values are untrusted: stringify, never interpret. */
function renderMetadataValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (Array.isArray(value)) return value.map(String).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/**
 * Only http(s) links become anchors. A scanner rule can carry an arbitrary
 * `helpUri`, and `javascript:` in an href is a script execution primitive.
 */
export function toSafeHttpUrl(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:"
      ? parsed.toString()
      : undefined;
  } catch {
    return undefined;
  }
}
