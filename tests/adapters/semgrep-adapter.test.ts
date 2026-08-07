import { describe, expect, it } from "vitest";

import { SemgrepAdapter } from "@/lib/security/adapters/semgrep-adapter";
import { loadFixture, testContext } from "../helpers/fixtures";

const adapter = new SemgrepAdapter();
const nativeJson = loadFixture("semgrep/result.json");
const sarif = loadFixture("semgrep/result.sarif");
const context = testContext("SEMGREP", { repositoryName: "payment-service" });

describe("SemgrepAdapter.canHandle", () => {
  it("claims its own native JSON and SARIF", () => {
    expect(adapter.canHandle(nativeJson)).toBe(true);
    expect(adapter.canHandle(sarif)).toBe(true);
  });

  it("claims a clean scan with no results", () => {
    expect(
      adapter.canHandle({ version: "1.95.0", results: [], errors: [], paths: {} }),
    ).toBe(true);
  });

  it("does not claim another scanner's output", () => {
    expect(adapter.canHandle(loadFixture("trivy/result.json"))).toBe(false);
    expect(adapter.canHandle(loadFixture("checkov/result.json"))).toBe(false);
    expect(adapter.canHandle(loadFixture("gitleaks/result.json"))).toBe(false);
    expect(adapter.canHandle(loadFixture("trivy/result.sarif"))).toBe(false);
  });

  it("does not throw on junk input", () => {
    expect(adapter.canHandle(null)).toBe(false);
    expect(adapter.canHandle("string")).toBe(false);
    expect(adapter.canHandle(42)).toBe(false);
    expect(adapter.canHandle([])).toBe(false);
  });
});

describe("SemgrepAdapter.parse (native JSON)", () => {
  it("normalizes results into the domain model", async () => {
    const findings = await adapter.parse(nativeJson, context);
    expect(findings).toHaveLength(2);

    const [sqlInjection] = findings;
    expect(sqlInjection.scanner).toBe("SEMGREP");
    expect(sqlInjection.category).toBe("SAST");
    expect(sqlInjection.title).toBe(
      "Detected SQL statement built from user-controlled input.",
    );
    expect(sqlInjection.ruleId).toBe(
      "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
    );
    expect(sqlInjection.file).toBe("src/payments/repository.py");
    expect(sqlInjection.startLine).toBe(142);
    expect(sqlInjection.endLine).toBe(144);
    expect(sqlInjection.cwe).toBe("CWE-89");
    expect(sqlInjection.repositoryName).toBe("payment-service");
    expect(sqlInjection.environment).toBe("production");
    expect(sqlInjection.commitSha).toBe(context.commitSha);
  });

  it("promotes ERROR + HIGH impact to CRITICAL, leaving plain ERROR at HIGH", async () => {
    const [critical] = await adapter.parse(nativeJson, context);
    expect(critical.severity).toBe("CRITICAL");

    const plainError = await adapter.parse(
      {
        results: [
          {
            check_id: "rule.a",
            path: "a.py",
            start: { line: 1 },
            end: { line: 1 },
            extra: {
              message: "issue",
              severity: "ERROR",
              metadata: { impact: "MEDIUM" },
            },
          },
        ],
      },
      context,
    );
    expect(plainError[0].severity).toBe("HIGH");
  });

  it("does not promote when confidence is LOW", async () => {
    const findings = await adapter.parse(
      {
        results: [
          {
            check_id: "rule.b",
            path: "b.py",
            start: { line: 1 },
            end: { line: 1 },
            extra: {
              message: "issue",
              severity: "ERROR",
              metadata: { impact: "HIGH", confidence: "LOW" },
            },
          },
        ],
      },
      context,
    );
    expect(findings[0].severity).toBe("HIGH");
  });

  it("maps WARNING to MEDIUM", async () => {
    const findings = await adapter.parse(nativeJson, context);
    expect(findings[1].severity).toBe("MEDIUM");
    expect(findings[1].cwe).toBe("CWE-327");
  });

  it("uses Semgrep's autofix as remediation and never invents one", async () => {
    const findings = await adapter.parse(nativeJson, context);
    expect(findings[0].remediation).toBe("Use a parameterised query.");
    expect(findings[1].remediation).toBeUndefined();
  });

  it("uses the native fingerprint so identity survives line drift", async () => {
    const [original] = await adapter.parse(nativeJson, context);

    const moved = structuredClone(nativeJson) as {
      results: Array<{ start: { line: number } }>;
    };
    moved.results[0].start.line = 900;

    const [afterMove] = await adapter.parse(moved, context);
    expect(afterMove.fingerprint).toBe(original.fingerprint);
  });

  it("keeps OWASP and confidence metadata without leaking source code", async () => {
    const [finding] = await adapter.parse(nativeJson, context);
    expect(finding.metadata?.owasp).toEqual(["A03:2021 - Injection"]);
    expect(finding.metadata?.confidence).toBe("HIGH");
    // `extra.lines` contains the matched source line — it must not be stored.
    expect(JSON.stringify(finding)).not.toContain("SELECT * FROM");
  });

  it("skips malformed result entries rather than throwing", async () => {
    const findings = await adapter.parse(
      { results: [null, "nonsense", 7, { check_id: "ok", path: "a.py" }] },
      context,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("ok");
  });

  it("returns an empty list for a clean scan", async () => {
    expect(await adapter.parse({ results: [] }, context)).toEqual([]);
  });
});

describe("SemgrepAdapter.parse (SARIF)", () => {
  it("produces SAST findings from SARIF too", async () => {
    const findings = await adapter.parse(sarif, context);
    expect(findings).toHaveLength(2);
    expect(findings.every((finding) => finding.category === "SAST")).toBe(true);
    expect(findings[0].severity).toBe("CRITICAL");
    expect(findings[0].cwe).toBe("CWE-89");
  });
});
