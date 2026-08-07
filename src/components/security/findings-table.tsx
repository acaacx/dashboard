"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  categoryLabel,
  scannerLabel,
  severityLabel,
  statusLabel,
  type FindingStatus,
  type Severity,
} from "@/domain/security/enums";
import type { Page, SecurityFinding } from "@/domain/security/finding";
import { CategoryBadge, ScannerBadge, SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/panel";
import { formatDate } from "@/lib/format";
import type { FilterOptions } from "@/lib/security/repository/security-finding-repository";
import type { SetFindingStatusAction } from "@/lib/security/status-change";
import { FindingDetails } from "./finding-details";

/**
 * Findings explorer: filters, search, sorting, pagination and the detail
 * drawer.
 *
 * All filtering happens SERVER-SIDE. This component builds a query string and
 * renders whatever /api/security/findings returns; it never filters, sorts or
 * counts an array locally. That is what makes the table honest at any dataset
 * size — page 3 of a 10,000-finding result costs the same as page 1.
 */

const SEVERITY_OPTIONS: Severity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
  "UNKNOWN",
];

const STATUS_OPTIONS: FindingStatus[] = [
  "OPEN",
  "RESOLVED",
  "ACCEPTED_RISK",
  "FALSE_POSITIVE",
  "SUPPRESSED",
];

export interface FindingsQueryState {
  severity: Severity[];
  status: FindingStatus[];
  scanner: string;
  category: string;
  repository: string;
  environment: string;
  search: string;
  page: number;
  sortBy: "severity" | "lastDetectedAt" | "firstDetectedAt" | "title";
  sortDirection: "asc" | "desc";
}

export const DEFAULT_QUERY_STATE: FindingsQueryState = {
  severity: [],
  status: ["OPEN"],
  scanner: "",
  category: "",
  repository: "",
  environment: "",
  search: "",
  page: 1,
  sortBy: "severity",
  sortDirection: "desc",
};

export function buildFindingsQuery(state: FindingsQueryState): string {
  const params = new URLSearchParams();
  if (state.severity.length) params.set("severity", state.severity.join(","));
  if (state.status.length) params.set("status", state.status.join(","));
  if (state.scanner) params.set("scanner", state.scanner);
  if (state.category) params.set("category", state.category);
  if (state.repository) params.set("repository", state.repository);
  if (state.environment) params.set("environment", state.environment);
  if (state.search.trim()) params.set("search", state.search.trim());
  if (state.page > 1) params.set("page", String(state.page));
  params.set("sortBy", state.sortBy);
  params.set("sortDirection", state.sortDirection);
  return params.toString();
}

export function FindingsTable({
  initialResult,
  filterOptions,
  initialSelected,
  initialState = DEFAULT_QUERY_STATE,
  setStatusAction,
}: {
  initialResult: Page<SecurityFinding>;
  filterOptions: FilterOptions;
  initialSelected?: SecurityFinding | null;
  initialState?: FindingsQueryState;
  /**
   * Server Action, injected by the page. Passing it as a prop rather than
   * importing it keeps this component and its tests free of a server runtime.
   */
  setStatusAction?: SetFindingStatusAction;
}) {
  const [state, setState] = useState<FindingsQueryState>(initialState);
  const [result, setResult] = useState(initialResult);
  const [selected, setSelected] = useState<SecurityFinding | null>(
    initialSelected ?? null,
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [refreshToken, setRefreshToken] = useState(0);
  const router = useRouter();

  // Skip the fetch triggered by the initial render: the server already
  // supplied that exact result.
  const isFirstRender = useRef(true);
  const abortRef = useRef<AbortController | null>(null);

  const queryString = useMemo(() => buildFindingsQuery(state), [state]);

  useEffect(() => {
    if (isFirstRender.current) {
      isFirstRender.current = false;
      return;
    }

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    // Debounce so typing in the search box does not fire a request per keypress.
    const timer = setTimeout(() => {
      setLoading(true);
      fetch(`/api/security/findings?${queryString}`, {
        signal: controller.signal,
        headers: { accept: "application/json" },
      })
        .then(async (response) => {
          if (!response.ok) throw new Error(`Request failed (${response.status})`);
          return (await response.json()) as Page<SecurityFinding>;
        })
        .then((next) => {
          setResult(next);
          setError(undefined);
        })
        .catch((cause: unknown) => {
          if (cause instanceof DOMException && cause.name === "AbortError") return;
          setError("Could not load findings.");
        })
        .finally(() => setLoading(false));
    }, 200);

    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [queryString, refreshToken]);

  const handleStatusChanged = useCallback(
    (updated: SecurityFinding) => {
      // Show what the server actually returned, never an optimistic guess.
      setSelected(updated);
      // Re-run the current query: a newly accepted finding drops out of the
      // default OPEN filter on its own.
      setRefreshToken((token) => token + 1);
      // Re-render the server page so the "Accepted risk" and "Total open" stat
      // tiles stop showing pre-change counts. This component seeds `result`
      // from props into state, so a fresh initialResult prop is ignored and the
      // user's filters survive.
      router.refresh();
    },
    [router],
  );

  const patch = useCallback(
    (next: Partial<FindingsQueryState>) => {
      setState((current) => ({
        ...current,
        ...next,
        // Any filter change resets to page 1; staying on page 7 of a result
        // that now has two pages shows an empty table for no reason.
        page: next.page ?? 1,
      }));
    },
    [],
  );

  const toggleSeverity = useCallback(
    (severity: Severity) => {
      setState((current) => ({
        ...current,
        page: 1,
        severity: current.severity.includes(severity)
          ? current.severity.filter((entry) => entry !== severity)
          : [...current.severity, severity],
      }));
    },
    [],
  );

  const toggleStatus = useCallback((status: FindingStatus) => {
    setState((current) => ({
      ...current,
      page: 1,
      status: current.status.includes(status)
        ? current.status.filter((entry) => entry !== status)
        : [...current.status, status],
    }));
  }, []);

  const hasFilters =
    state.severity.length > 0 ||
    state.search.trim() !== "" ||
    state.scanner !== "" ||
    state.category !== "" ||
    state.repository !== "" ||
    state.environment !== "" ||
    state.status.join(",") !== DEFAULT_QUERY_STATE.status.join(",");

  const from = result.total === 0 ? 0 : (result.page - 1) * result.pageSize + 1;
  const to = Math.min(result.page * result.pageSize, result.total);

  return (
    <div>
      <div className="border-line space-y-3 border-b px-5 py-4">
        <div className="flex flex-wrap items-center gap-2">
          <label className="relative flex-1 basis-64">
            <span className="sr-only">Search findings</span>
            <input
              type="search"
              value={state.search}
              onChange={(event) => patch({ search: event.target.value })}
              placeholder="Search title, CVE, CWE, repository, file, resource, rule ID"
              className="border-line bg-surface-raised text-ink placeholder:text-ink-faint focus:border-accent/50 w-full rounded border px-3 py-1.5 text-sm outline-none"
            />
          </label>

          <Select
            label="Scanner"
            value={state.scanner}
            onChange={(value) => patch({ scanner: value })}
            options={filterOptions.scanners.map((scanner) => ({
              value: scanner,
              label: scannerLabel(scanner),
            }))}
            allLabel="All scanners"
          />
          <Select
            label="Category"
            value={state.category}
            onChange={(value) => patch({ category: value })}
            options={filterOptions.categories.map((category) => ({
              value: category,
              label: categoryLabel(category),
            }))}
            allLabel="All categories"
          />
          <Select
            label="Repository"
            value={state.repository}
            onChange={(value) => patch({ repository: value })}
            options={filterOptions.repositories.map((repository) => ({
              value: repository,
              label: repository,
            }))}
            allLabel="All repositories"
          />
          <Select
            label="Environment"
            value={state.environment}
            onChange={(value) => patch({ environment: value })}
            options={filterOptions.environments.map((environment) => ({
              value: environment,
              label: environment,
            }))}
            allLabel="All environments"
          />
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <ChipGroup label="Severity">
            {SEVERITY_OPTIONS.map((severity) => (
              <Chip
                key={severity}
                active={state.severity.includes(severity)}
                onClick={() => toggleSeverity(severity)}
              >
                {severityLabel(severity)}
              </Chip>
            ))}
          </ChipGroup>

          <ChipGroup label="Status">
            {STATUS_OPTIONS.map((status) => (
              <Chip
                key={status}
                active={state.status.includes(status)}
                onClick={() => toggleStatus(status)}
              >
                {statusLabel(status)}
              </Chip>
            ))}
          </ChipGroup>

          {hasFilters && (
            <button
              type="button"
              onClick={() => setState(DEFAULT_QUERY_STATE)}
              className="text-accent ml-auto font-mono text-[11px] hover:underline"
            >
              Reset filters
            </button>
          )}
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[1040px] border-collapse text-left">
          <thead>
            <tr className="border-line text-ink-faint border-b">
              <Th className="w-[104px]">Severity</Th>
              <Th>Finding</Th>
              <Th className="w-[92px]">Category</Th>
              <Th className="w-[92px]">Scanner</Th>
              <Th className="w-[170px]">Repository / Resource</Th>
              <Th className="w-[100px]">Environment</Th>
              <Th className="w-[104px]">Status</Th>
              <SortableTh
                className="w-[112px]"
                active={state.sortBy === "firstDetectedAt"}
                direction={state.sortDirection}
                onClick={() =>
                  patch({
                    sortBy: "firstDetectedAt",
                    sortDirection:
                      state.sortBy === "firstDetectedAt" &&
                      state.sortDirection === "desc"
                        ? "asc"
                        : "desc",
                    page: state.page,
                  })
                }
              >
                First detected
              </SortableTh>
              <SortableTh
                className="w-[112px]"
                active={state.sortBy === "lastDetectedAt"}
                direction={state.sortDirection}
                onClick={() =>
                  patch({
                    sortBy: "lastDetectedAt",
                    sortDirection:
                      state.sortBy === "lastDetectedAt" &&
                      state.sortDirection === "desc"
                        ? "asc"
                        : "desc",
                    page: state.page,
                  })
                }
              >
                Last detected
              </SortableTh>
            </tr>
          </thead>
          <tbody
            className={`divide-line divide-y transition-opacity ${
              loading ? "opacity-50" : "opacity-100"
            }`}
          >
            {result.items.map((finding) => (
              <tr
                key={finding.id}
                tabIndex={0}
                role="button"
                onClick={() => setSelected(finding)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    setSelected(finding);
                  }
                }}
                className="hover:bg-surface-hover cursor-pointer transition-colors"
              >
                <Td>
                  <SeverityBadge severity={finding.severity} />
                </Td>
                <Td>
                  <p className="text-ink max-w-[420px] truncate text-sm">
                    {finding.title}
                  </p>
                  <p className="text-ink-faint mt-0.5 max-w-[420px] truncate font-mono text-[11px]">
                    {finding.cve ?? finding.ruleId ?? finding.file ?? "—"}
                  </p>
                </Td>
                <Td>
                  <CategoryBadge category={finding.category} />
                </Td>
                <Td>
                  <ScannerBadge scanner={finding.scanner} />
                </Td>
                <Td>
                  <span className="text-ink-muted block max-w-[170px] truncate font-mono text-[11px]">
                    {finding.repositoryName ?? "—"}
                  </span>
                  {/* Only when it adds information: a filesystem scan's
                      artifact name is often just the repository name again. */}
                  {finding.resource &&
                    finding.resource !== finding.repositoryName && (
                      <span className="text-ink-faint block max-w-[170px] truncate font-mono text-[10px]">
                        {finding.resource}
                      </span>
                    )}
                </Td>
                <Td>
                  <span className="text-ink-muted font-mono text-[11px]">
                    {finding.environment ?? "—"}
                  </span>
                </Td>
                <Td>
                  <StatusBadge status={finding.status} />
                </Td>
                <Td>
                  <span className="text-ink-muted font-mono text-[11px]">
                    {formatDate(finding.firstDetectedAt)}
                  </span>
                </Td>
                <Td>
                  <span className="text-ink-muted font-mono text-[11px]">
                    {formatDate(finding.lastDetectedAt)}
                  </span>
                </Td>
              </tr>
            ))}
          </tbody>
        </table>

        {result.items.length === 0 && !loading && (
          <EmptyState
            title="No findings match these filters."
            hint="Try clearing a filter, or widen the status selection beyond Open."
          />
        )}
      </div>

      <div className="border-line flex flex-wrap items-center justify-between gap-3 border-t px-5 py-3">
        <p className="text-ink-faint font-mono text-[11px]">
          {error ? (
            <span className="text-fail">{error}</span>
          ) : (
            <>
              {from}–{to} of {result.total}
            </>
          )}
        </p>

        <div className="flex items-center gap-1.5">
          <PageButton
            disabled={result.page <= 1}
            onClick={() => patch({ page: result.page - 1 })}
          >
            Previous
          </PageButton>
          <span className="text-ink-faint px-2 font-mono text-[11px]">
            {result.page} / {result.totalPages}
          </span>
          <PageButton
            disabled={result.page >= result.totalPages}
            onClick={() => patch({ page: result.page + 1 })}
          >
            Next
          </PageButton>
        </div>
      </div>

      {selected && (
        <FindingDetails
          finding={selected}
          onClose={() => setSelected(null)}
          onApplyStatus={setStatusAction}
          onStatusChanged={handleStatusChanged}
        />
      )}
    </div>
  );
}

function Th({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <th
      scope="col"
      className={`px-3 py-2.5 font-mono text-[10px] font-medium tracking-[0.12em] uppercase ${className}`}
    >
      {children}
    </th>
  );
}

function SortableTh({
  children,
  active,
  direction,
  onClick,
  className = "",
}: {
  children: React.ReactNode;
  active: boolean;
  direction: "asc" | "desc";
  onClick: () => void;
  className?: string;
}) {
  return (
    <th
      scope="col"
      aria-sort={active ? (direction === "asc" ? "ascending" : "descending") : "none"}
      className={`px-3 py-2.5 font-mono text-[10px] font-medium tracking-[0.12em] uppercase ${className}`}
    >
      <button
        type="button"
        onClick={onClick}
        className={`hover:text-ink flex items-center gap-1 ${
          active ? "text-accent" : ""
        }`}
      >
        {children}
        <span aria-hidden className="text-[9px]">
          {active ? (direction === "asc" ? "▲" : "▼") : "↕"}
        </span>
      </button>
    </th>
  );
}

function Td({ children }: { children: React.ReactNode }) {
  return <td className="px-3 py-2.5 align-top">{children}</td>;
}

function Select({
  label,
  value,
  onChange,
  options,
  allLabel,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
  allLabel: string;
}) {
  return (
    <label className="flex items-center gap-1.5">
      <span className="sr-only">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="border-line bg-surface-raised text-ink-muted focus:border-accent/50 rounded border px-2 py-1.5 font-mono text-[11px] outline-none"
      >
        <option value="">{allLabel}</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function ChipGroup({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-ink-faint font-mono text-[10px] tracking-[0.12em] uppercase">
        {label}
      </span>
      <div className="flex flex-wrap gap-1">{children}</div>
    </div>
  );
}

function Chip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`rounded border px-1.5 py-0.5 font-mono text-[10px] tracking-wide uppercase transition-colors ${
        active
          ? "border-accent/50 bg-accent/12 text-accent"
          : "border-line text-ink-faint hover:border-line-strong hover:text-ink-muted"
      }`}
    >
      {children}
    </button>
  );
}

function PageButton({
  children,
  disabled,
  onClick,
}: {
  children: React.ReactNode;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className="border-line text-ink-muted hover:border-line-strong hover:text-ink rounded border px-2.5 py-1 font-mono text-[11px] transition-colors disabled:cursor-not-allowed disabled:opacity-40"
    >
      {children}
    </button>
  );
}
