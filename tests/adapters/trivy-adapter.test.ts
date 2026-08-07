import { describe, expect, it } from "vitest";

import { TrivyAdapter } from "@/lib/security/adapters/trivy-adapter";
import { loadFixture, testContext } from "../helpers/fixtures";

const adapter = new TrivyAdapter();
const nativeJson = loadFixture("trivy/result.json");
const sarif = loadFixture("trivy/result.sarif");
const context = testContext("TRIVY", { repositoryName: "order-service" });

describe("TrivyAdapter.canHandle", () => {
  it("claims Trivy native JSON and SARIF", () => {
    expect(adapter.canHandle(nativeJson)).toBe(true);
    expect(adapter.canHandle(sarif)).toBe(true);
  });

  it("does not claim other scanners", () => {
    expect(adapter.canHandle(loadFixture("semgrep/result.json"))).toBe(false);
    expect(adapter.canHandle(loadFixture("checkov/result.json"))).toBe(false);
    expect(adapter.canHandle(loadFixture("gitleaks/result.json"))).toBe(false);
    expect(adapter.canHandle(null)).toBe(false);
  });
});

describe("TrivyAdapter.parse (native JSON)", () => {
  it("assigns a category per result class, not per scanner", async () => {
    const findings = await adapter.parse(nativeJson, context);

    const byRule = new Map(findings.map((finding) => [finding.ruleId, finding]));

    // One report, four classes, four categories.
    expect(byRule.get("CVE-2026-5678")?.category).toBe("CONTAINER"); // os-pkgs
    expect(byRule.get("CVE-2026-3456")?.category).toBe("SCA"); // lang-pkgs
    expect(byRule.get("DS002")?.category).toBe("CONTAINER"); // dockerfile config
    expect(byRule.get("generic-api-key")?.category).toBe("SECRET");
  });

  it("carries package and fix information for dependency findings", async () => {
    const findings = await adapter.parse(nativeJson, context);
    const lodash = findings.find((finding) => finding.packageName === "lodash");

    expect(lodash).toBeDefined();
    expect(lodash?.packageVersion).toBe("4.17.20");
    expect(lodash?.fixedVersion).toBe("4.17.21");
    expect(lodash?.cve).toBe("CVE-2026-3456");
    expect(lodash?.cwe).toBe("CWE-1321");
    expect(lodash?.severity).toBe("MEDIUM");
    expect(lodash?.file).toBe("app/node_modules/lodash/package.json");
  });

  it("prefers vendor severity and falls back to the CVSS score", async () => {
    const [openssl] = await adapter.parse(nativeJson, context);
    expect(openssl.severity).toBe("HIGH");

    const cvssOnly = await adapter.parse(
      {
        SchemaVersion: 2,
        ArtifactName: "x",
        Results: [
          {
            Target: "t",
            Class: "lang-pkgs",
            Vulnerabilities: [
              {
                VulnerabilityID: "CVE-2026-0001",
                PkgName: "p",
                CVSS: { nvd: { V3Score: 9.4 } },
              },
            ],
          },
        ],
      },
      context,
    );
    expect(cvssOnly[0].severity).toBe("CRITICAL");
  });

  it("uses Trivy's Resolution text as remediation", async () => {
    const findings = await adapter.parse(nativeJson, context);
    const dockerfile = findings.find((finding) => finding.ruleId === "DS002");
    expect(dockerfile?.remediation).toBe("Add 'USER app' before the entrypoint.");
    expect(dockerfile?.startLine).toBe(1);
    expect(dockerfile?.resource).toBe(
      "registry.example.invalid/order-service:1.14.2",
    );
  });

  it("records the container image as the resource for image scans", async () => {
    const [openssl] = await adapter.parse(nativeJson, context);
    expect(openssl.resource).toBe(
      "registry.example.invalid/order-service:1.14.2",
    );
  });

  it("never stores the matched value of a detected secret", async () => {
    const findings = await adapter.parse(nativeJson, context);
    const secret = findings.find((finding) => finding.category === "SECRET");

    expect(secret).toBeDefined();
    expect(secret?.metadata?.redacted).toBe(true);
    expect(JSON.stringify(secret)).not.toContain("REDACTED-TEST-PLACEHOLDER");
  });

  it("skips malformed results instead of throwing", async () => {
    const findings = await adapter.parse(
      {
        SchemaVersion: 2,
        Results: [null, 5, { Target: "t", Class: "lang-pkgs", Vulnerabilities: "no" }],
      },
      context,
    );
    expect(findings).toEqual([]);
  });

  it("returns nothing for a clean scan", async () => {
    expect(
      await adapter.parse(
        { SchemaVersion: 2, ArtifactName: "clean", Results: [] },
        context,
      ),
    ).toEqual([]);
  });
});

describe("TrivyAdapter.parse (SARIF)", () => {
  it("recovers categories from rule tags", async () => {
    const findings = await adapter.parse(sarif, context);
    expect(findings).toHaveLength(2);
    expect(findings[0].category).toBe("CONTAINER");
    expect(findings[0].cve).toBe("CVE-2026-5678");
    expect(findings[1].category).toBe("IAC");
  });
});
