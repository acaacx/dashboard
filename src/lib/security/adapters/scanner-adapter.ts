import type { ScannerType } from "@/domain/security/enums";
import { UnsupportedScannerError } from "@/domain/security/errors";
import type { ScanContext, SecurityFinding } from "@/domain/security/finding";

export type ScanResultFormat = "sarif" | "json";

/**
 * The contract every scanner integration implements.
 *
 * An adapter is the ONLY place allowed to know a scanner's output shape.
 * Everything above it — repository, service, API, UI — deals exclusively in
 * `SecurityFinding`. Adding a scanner therefore never requires a UI change.
 */
export interface ScannerAdapter {
  readonly scanner: ScannerType;

  /** Formats this adapter can read, for documentation and diagnostics. */
  readonly formats: readonly ScanResultFormat[];

  /**
   * Cheap structural sniff. Must not throw and must not mutate `input`.
   * Used to route a payload when the caller did not declare the scanner, and
   * to reject a payload that declares the wrong one.
   */
  canHandle(input: unknown): boolean;

  /**
   * Convert scanner output into normalized findings.
   *
   * Findings come back with lifecycle fields initialised from the scan context
   * (`status: OPEN`, `firstDetectedAt === lastDetectedAt === scannedAt`).
   * Reconciling those against history is the ingestion service's job, not the
   * adapter's — an adapter has no memory of previous scans.
   */
  parse(input: unknown, context: ScanContext): Promise<SecurityFinding[]>;
}

/**
 * Registry of available adapters.
 *
 * Registration is the single wiring step for a new scanner (step 7 of the
 * "adding a scanner" checklist in the README).
 */
export class ScannerAdapterRegistry {
  private readonly adapters = new Map<ScannerType, ScannerAdapter>();

  constructor(adapters: readonly ScannerAdapter[] = []) {
    adapters.forEach((adapter) => this.register(adapter));
  }

  register(adapter: ScannerAdapter): this {
    this.adapters.set(adapter.scanner, adapter);
    return this;
  }

  has(scanner: ScannerType): boolean {
    return this.adapters.has(scanner);
  }

  list(): ScannerAdapter[] {
    return [...this.adapters.values()];
  }

  /** Supported scanner types, excluding the UNKNOWN sentinel. */
  supportedScanners(): ScannerType[] {
    return this.list()
      .map((adapter) => adapter.scanner)
      .filter((scanner) => scanner !== "UNKNOWN");
  }

  /** @throws UnsupportedScannerError when no adapter is registered. */
  get(scanner: ScannerType): ScannerAdapter {
    const adapter = this.adapters.get(scanner);
    if (!adapter) throw new UnsupportedScannerError(scanner);
    return adapter;
  }

  /**
   * Resolve by declared scanner, falling back to structural sniffing.
   *
   * A declared scanner is honoured even when `canHandle` disagrees only if no
   * other adapter claims the payload; otherwise the payload wins. This matters
   * because CI configuration drifts — a workflow labelled `trivy` that uploads
   * a Semgrep SARIF should be normalized correctly rather than dropped.
   */
  resolve(input: unknown, declared?: ScannerType): ScannerAdapter {
    if (declared && declared !== "UNKNOWN") {
      const adapter = this.adapters.get(declared);
      if (adapter?.canHandle(input)) return adapter;

      const claimant = this.list().find((candidate) =>
        candidate.canHandle(input),
      );
      if (claimant) return claimant;

      if (adapter) return adapter;
      throw new UnsupportedScannerError(declared);
    }

    const claimant = this.list().find((candidate) => candidate.canHandle(input));
    if (claimant) return claimant;

    throw new UnsupportedScannerError(declared ?? "UNKNOWN");
  }
}
