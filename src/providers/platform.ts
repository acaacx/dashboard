import type { SecurityService } from "@/lib/security/services/security-service";

/**
 * Provider architecture.
 *
 * The dashboard's job is to combine three independent sources:
 *
 *   DevSecOpsPlatform
 *        ├── GitHub    (repositories, workflow runs, deployments)
 *        ├── Azure     (resources, environments, cost/health)
 *        └── Security  (Semgrep, Trivy, Checkov, Gitleaks, …)
 *
 * Each is a separate provider behind its own narrow interface rather than
 * methods on one growing class. The security provider is implemented today;
 * GitHub and Azure are declared and stubbed so the pages that will need them
 * can already ask "is this configured?" and degrade honestly instead of
 * inventing data.
 */

export interface OperationalProvider {
  readonly name: string;
  /** False when credentials or endpoints are absent. */
  isConfigured(): boolean;
}

export interface WorkflowRunSummary {
  id: string;
  repositoryName: string;
  workflowName: string;
  status: "QUEUED" | "IN_PROGRESS" | "SUCCESS" | "FAILURE" | "CANCELLED";
  startedAt: string;
  completedAt?: string;
  url?: string;
}

export interface GitHubProvider extends OperationalProvider {
  listWorkflowRuns(repositoryName?: string): Promise<WorkflowRunSummary[]>;
}

export interface AzureResourceSummary {
  azureResourceId: string;
  name: string;
  type: string;
  resourceGroup?: string;
  subscriptionId?: string;
  environment?: string;
}

export interface AzureProvider extends OperationalProvider {
  listResources(environment?: string): Promise<AzureResourceSummary[]>;
}

/**
 * Stub providers.
 *
 * They report `isConfigured() === false` and return nothing. This is the
 * deliberate alternative to mock GitHub/Azure data: a page can show "not
 * connected" truthfully, and no fabricated deployment ever gets mistaken for a
 * real one.
 */
export class UnconfiguredGitHubProvider implements GitHubProvider {
  readonly name = "github";
  isConfigured(): boolean {
    return false;
  }
  async listWorkflowRuns(): Promise<WorkflowRunSummary[]> {
    return [];
  }
}

export class UnconfiguredAzureProvider implements AzureProvider {
  readonly name = "azure";
  isConfigured(): boolean {
    return false;
  }
  async listResources(): Promise<AzureResourceSummary[]> {
    return [];
  }
}

export interface DevSecOpsPlatformOptions {
  security: SecurityService;
  github?: GitHubProvider;
  azure?: AzureProvider;
}

/**
 * Thin aggregator. It holds providers and exposes their configuration state; it
 * deliberately does NOT wrap every provider method, which is how this kind of
 * class turns into the god object the architecture is trying to avoid.
 */
export class DevSecOpsPlatform {
  readonly security: SecurityService;
  readonly github: GitHubProvider;
  readonly azure: AzureProvider;

  constructor(options: DevSecOpsPlatformOptions) {
    this.security = options.security;
    this.github = options.github ?? new UnconfiguredGitHubProvider();
    this.azure = options.azure ?? new UnconfiguredAzureProvider();
  }

  providerStatus(): Array<{ name: string; configured: boolean }> {
    return [
      { name: "security", configured: true },
      { name: this.github.name, configured: this.github.isConfigured() },
      { name: this.azure.name, configured: this.azure.isConfigured() },
    ];
  }
}
