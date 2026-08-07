import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type { ScannerType } from "@/domain/security/enums";
import type { ScanContext } from "@/domain/security/finding";

const FIXTURE_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "fixtures",
);

/** Load a fixture by path relative to tests/fixtures, e.g. "trivy/result.json". */
export function loadFixture(relativePath: string): unknown {
  return JSON.parse(
    readFileSync(path.join(FIXTURE_ROOT, relativePath), "utf8"),
  );
}

/** A fixed scan context so fingerprints in tests are stable. */
export function testContext(
  scanner: ScannerType,
  overrides: Partial<ScanContext> = {},
): ScanContext {
  return {
    scanner,
    repositoryId: "repo_test",
    repositoryName: "test-service",
    branch: "main",
    commitSha: "0123456789abcdef0123456789abcdef01234567",
    workflowRunId: "42",
    workflowRunUrl: "https://github.com/example/test/actions/runs/42",
    applicationId: "app_test",
    environment: "production",
    scannedAt: "2026-08-01T12:00:00.000Z",
    ...overrides,
  };
}
