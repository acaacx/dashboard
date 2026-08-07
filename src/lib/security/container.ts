import "server-only";

import {
  NoopAssetCorrelationService,
  type AssetCorrelationService,
} from "@/domain/security/inventory";
import { DevSecOpsPlatform } from "@/providers/platform";
import {
  createDefaultAdapterRegistry,
  type ScannerAdapterRegistry,
} from "./adapters";
import { InMemorySecurityFindingRepository } from "./repository/memory-security-finding-repository";
import { InMemoryScanRunRepository } from "./repository/scan-run-repository";
import type { SecurityFindingRepository } from "./repository/security-finding-repository";
import type { ScanRunRepository } from "./repository/scan-run-repository";
import { ScanIngestionService } from "./services/scan-ingestion-service";
import { SecurityService } from "./services/security-service";
import { seedMockData } from "./mock/seed-mock-data";

/**
 * Composition root for the security platform.
 *
 * This is the ONE place that decides which implementations are in play. Pages,
 * API routes and services depend on interfaces; swapping the in-memory store
 * for PostgreSQL, or the no-op correlation service for a real inventory client,
 * is an edit to this file and nothing else.
 *
 * Server-only: importing it from a client component is a build error, which is
 * the guardrail that keeps scanner-parsing code out of the browser bundle.
 */

export interface SecurityContainer {
  findingRepository: SecurityFindingRepository;
  scanRunRepository: ScanRunRepository;
  adapterRegistry: ScannerAdapterRegistry;
  correlationService: AssetCorrelationService;
  securityService: SecurityService;
  ingestionService: ScanIngestionService;
  /** GitHub + Azure + Security, behind one aggregator. */
  platform: DevSecOpsPlatform;
  /** True when the store was seeded with fabricated data. Surfaced in the UI. */
  usingMockData: boolean;
}

/**
 * `mock` (default) seeds fabricated scan results so the dashboard is usable
 * without a pipeline. `live` starts empty and waits for real ingestion.
 */
export type SecurityDataSource = "mock" | "live";

export function configuredDataSource(): SecurityDataSource {
  return process.env.SECURITY_DATA_SOURCE === "live" ? "live" : "mock";
}

async function buildContainer(): Promise<SecurityContainer> {
  const findingRepository = new InMemorySecurityFindingRepository();
  const scanRunRepository = new InMemoryScanRunRepository();
  const adapterRegistry = createDefaultAdapterRegistry();

  // Replace with `new InventoryAssetCorrelationService(provider)` once an
  // InventoryProvider exists. See README "Inventory correlation".
  const correlationService = new NoopAssetCorrelationService();

  const securityService = new SecurityService(
    findingRepository,
    scanRunRepository,
    adapterRegistry.supportedScanners(),
  );

  const ingestionService = new ScanIngestionService(
    adapterRegistry,
    findingRepository,
    scanRunRepository,
    correlationService,
  );

  const usingMockData = configuredDataSource() === "mock";
  if (usingMockData) {
    await seedMockData(ingestionService, securityService);
  }

  // GitHub and Azure stay unconfigured until real credentials exist; the
  // platform reports that honestly rather than substituting invented data.
  const platform = new DevSecOpsPlatform({ security: securityService });

  return {
    findingRepository,
    scanRunRepository,
    adapterRegistry,
    correlationService,
    securityService,
    ingestionService,
    platform,
    usingMockData,
  };
}

/**
 * Cached on globalThis rather than in a module-level variable so the store
 * survives Next.js dev-server hot reloads. Without this, every edit would
 * reseed and every ingested finding would vanish mid-session.
 */
const CONTAINER_KEY = Symbol.for("dashboard.security.container");

type GlobalWithContainer = typeof globalThis & {
  [CONTAINER_KEY]?: Promise<SecurityContainer>;
};

export function getSecurityContainer(): Promise<SecurityContainer> {
  const globalRef = globalThis as GlobalWithContainer;
  globalRef[CONTAINER_KEY] ??= buildContainer();
  return globalRef[CONTAINER_KEY];
}

/** Test seam: drop the cached container so the next call rebuilds it. */
export function resetSecurityContainer(): void {
  const globalRef = globalThis as GlobalWithContainer;
  delete globalRef[CONTAINER_KEY];
}

export async function getSecurityService(): Promise<SecurityService> {
  return (await getSecurityContainer()).securityService;
}

export async function getScanIngestionService(): Promise<ScanIngestionService> {
  return (await getSecurityContainer()).ingestionService;
}
