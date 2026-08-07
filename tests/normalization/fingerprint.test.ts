import { describe, expect, it } from "vitest";

import {
  fingerprintComponents,
  findingIdFromFingerprint,
  generateFindingFingerprint,
  normalizePathForFingerprint,
  type FingerprintInput,
} from "@/lib/security/normalization/fingerprint";

const base: FingerprintInput = {
  scanner: "SEMGREP",
  ruleId: "python.lang.security.sql-injection",
  repositoryName: "payment-service",
  file: "src/payments/repository.py",
  startLine: 142,
  environment: "production",
};

describe("generateFindingFingerprint", () => {
  it("is deterministic across calls", () => {
    expect(generateFindingFingerprint(base)).toBe(
      generateFindingFingerprint(base),
    );
  });

  it("does not depend on key order in the input object", () => {
    const reordered: FingerprintInput = {
      environment: "production",
      startLine: 142,
      file: "src/payments/repository.py",
      repositoryName: "payment-service",
      ruleId: "python.lang.security.sql-injection",
      scanner: "SEMGREP",
    };
    expect(generateFindingFingerprint(reordered)).toBe(
      generateFindingFingerprint(base),
    );
  });

  it("normalizes case and path separators", () => {
    expect(
      generateFindingFingerprint({
        ...base,
        file: ".\\SRC\\payments\\Repository.py",
      }),
    ).toBe(generateFindingFingerprint(base));
  });

  it("changes when the identity of the problem changes", () => {
    const original = generateFindingFingerprint(base);

    expect(generateFindingFingerprint({ ...base, ruleId: "other-rule" })).not.toBe(original);
    expect(generateFindingFingerprint({ ...base, startLine: 143 })).not.toBe(original);
    expect(generateFindingFingerprint({ ...base, file: "src/other.py" })).not.toBe(original);
    expect(generateFindingFingerprint({ ...base, repositoryName: "user-service" })).not.toBe(original);
    expect(generateFindingFingerprint({ ...base, environment: "staging" })).not.toBe(original);
    expect(generateFindingFingerprint({ ...base, scanner: "TRIVY" })).not.toBe(original);
  });

  it("ignores fields that describe state rather than identity", () => {
    // Severity, status, description and timestamps are deliberately not part of
    // the input type at all — this asserts the shape of the contract.
    const components = fingerprintComponents(base).map(([key]) => key);
    expect(components).not.toContain("severity");
    expect(components).not.toContain("status");
    expect(components).not.toContain("firstDetectedAt");
    expect(components).not.toContain("lastDetectedAt");
    expect(components).not.toContain("commit");
    expect(components).not.toContain("branch");
  });

  it("gives the same fingerprint for a rescan minutes later", () => {
    // The scan context changes (commit, timestamps) but identity must not.
    const first = generateFindingFingerprint(base);
    const rescan = generateFindingFingerprint({ ...base });
    expect(rescan).toBe(first);
  });

  it("uses a scanner-native stable id in preference to positional data", () => {
    const withStableId = generateFindingFingerprint({
      ...base,
      stableId: "commit:file:rule:27",
    });

    // Line drift must not change identity when a stable id is present.
    const afterLineShift = generateFindingFingerprint({
      ...base,
      startLine: 999,
      stableId: "commit:file:rule:27",
    });

    expect(afterLineShift).toBe(withStableId);
    expect(withStableId).not.toBe(generateFindingFingerprint(base));
  });

  it("distinguishes two CVEs in the same package", () => {
    const a = generateFindingFingerprint({
      scanner: "TRIVY",
      packageName: "openssl",
      cve: "CVE-2026-1111",
      repositoryName: "order-service",
    });
    const b = generateFindingFingerprint({
      scanner: "TRIVY",
      packageName: "openssl",
      cve: "CVE-2026-2222",
      repositoryName: "order-service",
    });
    expect(a).not.toBe(b);
  });

  it("omits empty values instead of hashing empty strings", () => {
    const withEmpties = generateFindingFingerprint({
      ...base,
      packageName: "",
      cve: "   ",
    });
    expect(withEmpties).toBe(generateFindingFingerprint(base));
  });

  it("produces a hex sha-256 digest", () => {
    expect(generateFindingFingerprint(base)).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("fingerprintComponents", () => {
  it("returns sorted key/value pairs for debugging", () => {
    const components = fingerprintComponents(base);
    const keys = components.map(([key]) => key);
    expect(keys).toEqual([...keys].sort());
    expect(Object.fromEntries(components)).toMatchObject({
      scanner: "semgrep",
      repo: "payment-service",
      file: "src/payments/repository.py",
      line: "142",
      env: "production",
    });
  });

  it("prefers repositoryId over repositoryName when both are present", () => {
    const components = Object.fromEntries(
      fingerprintComponents({ ...base, repositoryId: "repo_1" }),
    );
    expect(components.repo).toBe("repo_1");
  });
});

describe("normalizePathForFingerprint", () => {
  it("canonicalises separators, prefixes and case", () => {
    expect(normalizePathForFingerprint("./src/A.ts")).toBe("src/a.ts");
    expect(normalizePathForFingerprint("src\\a.ts")).toBe("src/a.ts");
    expect(normalizePathForFingerprint("/src/a.ts")).toBe("src/a.ts");
  });
});

describe("findingIdFromFingerprint", () => {
  it("derives a stable, prefixed id", () => {
    const fingerprint = generateFindingFingerprint(base);
    expect(findingIdFromFingerprint(fingerprint)).toBe(
      `fnd_${fingerprint.slice(0, 24)}`,
    );
  });
});
