/**
 * Lightweight instrumentation seam.
 *
 * No agent, no exporter, no vendor SDK — this task explicitly does not install
 * an observability stack. What it does is make sure the interesting events
 * already have a single, typed choke point, so wiring OpenTelemetry or a
 * metrics backend later is a matter of registering a sink rather than hunting
 * for call sites.
 *
 * Safety rule: event attributes are counts, identifiers and enum values only.
 * Never scanner payloads, never secret material, never file contents.
 */

export type SecurityEventName =
  | "scan.ingestion.started"
  | "scan.ingestion.succeeded"
  | "scan.ingestion.failed"
  | "scan.findings.processed"
  | "scan.findings.created"
  | "scan.findings.reopened"
  | "scan.findings.resolved"
  | "scan.parser.error"
  | "db.query.retry";

export interface SecurityEvent {
  name: SecurityEventName;
  at: string;
  attributes: Record<string, string | number | boolean | undefined>;
}

export type SecurityEventSink = (event: SecurityEvent) => void;

const sinks: SecurityEventSink[] = [];
const counters = new Map<SecurityEventName, number>();

export function registerSecurityEventSink(sink: SecurityEventSink): () => void {
  sinks.push(sink);
  return () => {
    const index = sinks.indexOf(sink);
    if (index >= 0) sinks.splice(index, 1);
  };
}

export function recordSecurityEvent(
  name: SecurityEventName,
  attributes: SecurityEvent["attributes"] = {},
): void {
  counters.set(name, (counters.get(name) ?? 0) + 1);

  const event: SecurityEvent = {
    name,
    at: new Date().toISOString(),
    attributes,
  };

  for (const sink of sinks) {
    try {
      sink(event);
    } catch {
      // A broken telemetry sink must never break ingestion.
    }
  }
}

/** Snapshot of event counts since process start. Exposed for smoke checks. */
export function getSecurityEventCounters(): Record<string, number> {
  return Object.fromEntries(counters.entries());
}

export function resetSecurityEventCounters(): void {
  counters.clear();
}
