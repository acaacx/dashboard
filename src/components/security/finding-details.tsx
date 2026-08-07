"use client";

import { useEffect, useRef } from "react";

import { categoryLabel, scannerLabel } from "@/domain/security/enums";
import type { SecurityFinding } from "@/domain/security/finding";
import { ScannerBadge, SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { formatDateTime } from "@/lib/format";

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
}: {
  finding: SecurityFinding;
  onClose: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement>(null);

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
