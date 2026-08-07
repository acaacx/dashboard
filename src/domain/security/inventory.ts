/**
 * Inventory correlation contracts.
 *
 * The repository/Azure inventory is owned by another system and supplied later.
 * This file therefore contains *interfaces only* plus a deliberately inert
 * default implementation. Nothing here discovers, scans or enumerates
 * infrastructure, and nothing here guesses: correlation happens on stable IDs.
 *
 * Chain the dashboard eventually walks:
 *
 *   Finding -> Repository -> Application -> Environment -> Azure Resource
 *
 * Not every finding reaches the end of that chain. A Semgrep finding in a
 * library repo may never map to an Azure resource, and that is a valid, final
 * state — not a correlation failure.
 */

import type { SecurityFinding } from "./finding";

export interface InventoryRepository {
  repositoryId: string;
  repositoryName: string;
  applicationId?: string;
  defaultBranch?: string;
  url?: string;
}

export interface InventoryApplication {
  applicationId: string;
  name: string;
  ownerTeam?: string;
  environments?: string[];
}

export interface InventoryEnvironment {
  environmentId: string;
  name: string;
  applicationId?: string;
  subscriptionId?: string;
  resourceGroup?: string;
}

export interface InventoryAzureResource {
  azureResourceId: string;
  name: string;
  type: string;
  subscriptionId?: string;
  resourceGroup?: string;
  environmentId?: string;
  applicationId?: string;
}

/**
 * Read-only view onto the external inventory. Implemented later by whatever
 * owns the inventory data (API client, database view, cached snapshot).
 */
export interface InventoryProvider {
  getRepositoryById(repositoryId: string): Promise<InventoryRepository | null>;
  /**
   * Exact-match lookup by name. Implementations MUST NOT fuzzy match; a
   * near-miss silently attributing a critical finding to the wrong application
   * is worse than no correlation at all.
   */
  getRepositoryByName(
    repositoryName: string,
  ): Promise<InventoryRepository | null>;
  getApplicationById(applicationId: string): Promise<InventoryApplication | null>;
  getEnvironmentsByApplicationId(
    applicationId: string,
  ): Promise<InventoryEnvironment[]>;
  getAzureResourcesByEnvironmentId(
    environmentId: string,
  ): Promise<InventoryAzureResource[]>;
}

/** Everything the inventory could tell us about one finding. */
export interface CorrelatedAssets {
  repository?: InventoryRepository;
  application?: InventoryApplication;
  environment?: InventoryEnvironment;
  azureResources: InventoryAzureResource[];
}

export interface AssetCorrelationService {
  /** Enrich a single finding with inventory-derived identifiers. */
  correlate(finding: SecurityFinding): Promise<CorrelatedAssets>;
  /**
   * Fill in `applicationId`, `environment`, `subscriptionId` and
   * `resourceGroup` on findings where the inventory can supply them and the
   * finding does not already carry a value from the scan context.
   */
  enrich(findings: SecurityFinding[]): Promise<SecurityFinding[]>;
}

/**
 * The implementation used until a real inventory is wired in.
 *
 * It correlates nothing and enriches nothing, by design. It exists so callers
 * can depend on the interface today without a null check at every call site,
 * and so swapping in the real service is a container change rather than a
 * refactor.
 */
export class NoopAssetCorrelationService implements AssetCorrelationService {
  async correlate(): Promise<CorrelatedAssets> {
    return { azureResources: [] };
  }

  async enrich(findings: SecurityFinding[]): Promise<SecurityFinding[]> {
    return findings;
  }
}

/**
 * Reference implementation for when an InventoryProvider does exist.
 *
 * Strictly ID-driven: it walks repositoryId -> application -> environments ->
 * resources. `repositoryName` is used only as an exact-match fallback key,
 * which is safe because names are unique within a GitHub organization. Values
 * already present on the finding (i.e. asserted by CI) always win.
 */
export class InventoryAssetCorrelationService
  implements AssetCorrelationService
{
  constructor(private readonly inventory: InventoryProvider) {}

  async correlate(finding: SecurityFinding): Promise<CorrelatedAssets> {
    const repository = await this.lookupRepository(finding);
    if (!repository) return { azureResources: [] };

    const applicationId = finding.applicationId ?? repository.applicationId;
    if (!applicationId) return { repository, azureResources: [] };

    const application =
      (await this.inventory.getApplicationById(applicationId)) ?? undefined;

    const environments =
      await this.inventory.getEnvironmentsByApplicationId(applicationId);

    const environment = finding.environment
      ? environments.find((candidate) => candidate.name === finding.environment)
      : undefined;

    const azureResources = environment
      ? await this.inventory.getAzureResourcesByEnvironmentId(
          environment.environmentId,
        )
      : [];

    return { repository, application, environment, azureResources };
  }

  async enrich(findings: SecurityFinding[]): Promise<SecurityFinding[]> {
    return Promise.all(
      findings.map(async (finding) => {
        const assets = await this.correlate(finding);
        if (!assets.repository) return finding;

        return {
          ...finding,
          repositoryId: finding.repositoryId ?? assets.repository.repositoryId,
          applicationId:
            finding.applicationId ?? assets.repository.applicationId,
          environment: finding.environment ?? assets.environment?.name,
          subscriptionId:
            finding.subscriptionId ?? assets.environment?.subscriptionId,
          resourceGroup:
            finding.resourceGroup ?? assets.environment?.resourceGroup,
        };
      }),
    );
  }

  private async lookupRepository(
    finding: SecurityFinding,
  ): Promise<InventoryRepository | null> {
    if (finding.repositoryId) {
      return this.inventory.getRepositoryById(finding.repositoryId);
    }
    if (finding.repositoryName) {
      return this.inventory.getRepositoryByName(finding.repositoryName);
    }
    return null;
  }
}
