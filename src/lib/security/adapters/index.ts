import { CheckovAdapter } from "./checkov-adapter";
import { GitleaksAdapter } from "./gitleaks-adapter";
import { ScannerAdapterRegistry } from "./scanner-adapter";
import { SemgrepAdapter } from "./semgrep-adapter";
import { TrivyAdapter } from "./trivy-adapter";

export * from "./scanner-adapter";
export { CheckovAdapter } from "./checkov-adapter";
export { GitleaksAdapter } from "./gitleaks-adapter";
export { SemgrepAdapter } from "./semgrep-adapter";
export { TrivyAdapter } from "./trivy-adapter";

/**
 * Build the default registry.
 *
 * THIS IS THE WIRING POINT FOR A NEW SCANNER. Adding one means: extend
 * `ScannerType`, write the adapter, add fixtures and tests, then add one line
 * here. No UI file changes.
 */
export function createDefaultAdapterRegistry(): ScannerAdapterRegistry {
  return new ScannerAdapterRegistry([
    new SemgrepAdapter(),
    new TrivyAdapter(),
    new CheckovAdapter(),
    new GitleaksAdapter(),
  ]);
}
