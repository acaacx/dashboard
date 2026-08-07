import {
  categoryLabel,
  scannerLabel,
  severityLabel,
  statusLabel,
  type FindingCategory,
  type FindingStatus,
  type ScannerType,
  type Severity,
} from "@/domain/security/enums";
import {
  SEVERITY_BADGE_CLASS,
  SEVERITY_DOT_CLASS,
  STATUS_BADGE_CLASS,
} from "@/components/security/severity-tokens";

const BASE =
  "inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 font-mono text-[10px] font-medium tracking-wide uppercase whitespace-nowrap";

/**
 * Badges render already-normalized enum values. They never inspect a scanner
 * payload, and they never decide what category or severity something is —
 * that happened in an adapter long before this point.
 */

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`${BASE} ${SEVERITY_BADGE_CLASS[severity]}`}>
      <span
        aria-hidden
        className={`size-1.5 rounded-full ${SEVERITY_DOT_CLASS[severity]}`}
      />
      {severityLabel(severity)}
    </span>
  );
}

export function StatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span className={`${BASE} ${STATUS_BADGE_CLASS[status]}`}>
      {statusLabel(status)}
    </span>
  );
}

/**
 * Scanner and category badges are intentionally monochrome and label-driven:
 * an unrecognised value still renders correctly (title-cased), which is what
 * lets a new scanner appear in the UI with no UI change.
 */
export function ScannerBadge({ scanner }: { scanner: ScannerType | string }) {
  return (
    <span className="border-line-strong bg-surface-raised text-ink-muted inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] tracking-wide whitespace-nowrap">
      {scannerLabel(scanner)}
    </span>
  );
}

export function CategoryBadge({
  category,
}: {
  category: FindingCategory | string;
}) {
  return (
    <span className="border-line text-ink-faint inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] tracking-wide whitespace-nowrap">
      {categoryLabel(category)}
    </span>
  );
}

/** Used to mark seeded demo data so it is never mistaken for real findings. */
export function MockBadge() {
  return (
    <span className="border-accent/40 bg-accent/10 text-accent inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] font-medium tracking-[0.12em] uppercase">
      Mock data
    </span>
  );
}
