import { describe, expect, it } from "vitest";

import { InvalidSarifError } from "@/domain/security/errors";
import {
  detectScannerFromSarif,
  isSarifDocument,
  parseSarif,
  parseSarifDocument,
  sarifToolName,
} from "@/lib/security/parsers/sarif-parser";
import { loadFixture, testContext } from "../helpers/fixtures";

const semgrepSarif = loadFixture("semgrep/result.sarif");
const trivySarif = loadFixture("trivy/result.sarif");
const checkovSarif = loadFixture("checkov/result.sarif");

describe("isSarifDocument", () => {
  it("recognises SARIF and rejects native scanner formats", () => {
    expect(isSarifDocument(semgrepSarif)).toBe(true);
    expect(isSarifDocument(loadFixture("semgrep/result.json"))).toBe(false);
    expect(isSarifDocument(loadFixture("gitleaks/result.json"))).toBe(false);
    expect(isSarifDocument(null)).toBe(false);
    expect(isSarifDocument([])).toBe(false);
    expect(isSarifDocument({ runs: "not-an-array" })).toBe(false);
  });
});

describe("parseSarifDocument", () => {
  it("rejects payloads that are not SARIF", () => {
    expect(() => parseSarifDocument(null)).toThrow(InvalidSarifError);
    expect(() => parseSarifDocument({})).toThrow(InvalidSarifError);
    expect(() => parseSarifDocument({ runs: {} })).toThrow(InvalidSarifError);
  });

  it("rejects a SARIF version it cannot honestly claim to support", () => {
    expect(() =>
      parseSarifDocument({ version: "1.0.0", runs: [] }),
    ).toThrow(/only SARIF 2.1.0/);
  });

  it("resolves rule metadata by id and by index", () => {
    const byId = parseSarifDocument(semgrepSarif);
    expect(byId.runs[0].results[0].rule?.helpUri).toBe(
      "https://example.invalid/sqli",
    );

    const byIndex = parseSarifDocument({
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Example",
              rules: [{ id: "R1", shortDescription: { text: "First" } }],
            },
          },
          results: [{ ruleIndex: 0, message: { text: "hit" } }],
        },
      ],
    });
    expect(byIndex.runs[0].results[0].rule?.shortDescription).toBe("First");
  });

  it("survives missing optional structure without throwing", () => {
    const parsed = parseSarifDocument({
      version: "2.1.0",
      runs: [
        { tool: {}, results: [{ message: { text: "no rule, no location" } }] },
        { tool: { driver: { name: "X" } } },
      ],
    });

    expect(parsed.runs).toHaveLength(2);
    expect(parsed.runs[0].results[0].locations).toEqual([]);
    expect(parsed.runs[1].results).toEqual([]);
  });

  it("reads rules that live on tool extensions rather than the driver", () => {
    const parsed = parseSarifDocument({
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: { name: "Host" },
            extensions: [
              { name: "ext", rules: [{ id: "E1", helpUri: "https://e.invalid" }] },
            ],
          },
          results: [{ ruleId: "E1", message: { text: "from extension" } }],
        },
      ],
    });
    expect(parsed.runs[0].results[0].rule?.helpUri).toBe("https://e.invalid");
  });
});

describe("sarifToolName / detectScannerFromSarif", () => {
  it("identifies the producing tool", () => {
    expect(sarifToolName(semgrepSarif)).toBe("Semgrep OSS");
    expect(detectScannerFromSarif(semgrepSarif)).toBe("SEMGREP");
    expect(detectScannerFromSarif(trivySarif)).toBe("TRIVY");
    expect(detectScannerFromSarif(checkovSarif)).toBe("CHECKOV");
    expect(detectScannerFromSarif(loadFixture("gitleaks/result.sarif"))).toBe(
      "GITLEAKS",
    );
  });

  it("returns UNKNOWN for an unrecognised tool", () => {
    expect(
      detectScannerFromSarif({
        version: "2.1.0",
        runs: [{ tool: { driver: { name: "SomeFutureScanner" } }, results: [] }],
      }),
    ).toBe("UNKNOWN");
  });
});

describe("parseSarif", () => {
  const context = testContext("SEMGREP");

  it("normalizes results without any scanner-specific knowledge", () => {
    const findings = parseSarif(semgrepSarif, context, { category: "SAST" });

    expect(findings).toHaveLength(2);

    const [sqlInjection] = findings;
    expect(sqlInjection.title).toBe(
      "Detected SQL statement built from user-controlled input.",
    );
    expect(sqlInjection.file).toBe("src/payments/repository.py");
    expect(sqlInjection.startLine).toBe(142);
    expect(sqlInjection.endLine).toBe(144);
    expect(sqlInjection.cwe).toBe("CWE-89");
    expect(sqlInjection.category).toBe("SAST");
    expect(sqlInjection.status).toBe("OPEN");
    expect(sqlInjection.repositoryName).toBe("test-service");
    expect(sqlInjection.firstDetectedAt).toBe(context.scannedAt);
    expect(sqlInjection.lastDetectedAt).toBe(context.scannedAt);
  });

  it("prefers numeric security-severity over the SARIF level", () => {
    const [first, second] = parseSarif(semgrepSarif, context);
    // security-severity 9.1 outranks level "error" (which alone is HIGH).
    expect(first.severity).toBe("CRITICAL");
    // No security-severity on the second rule, so the level decides.
    expect(second.severity).toBe("MEDIUM");
  });

  it("carries only scanner-supplied remediation", () => {
    const [first, second] = parseSarif(semgrepSarif, context);
    expect(first.remediation).toBe("Use a parameterised query.");
    expect(second.remediation).toBeUndefined();
  });

  it("marks suppressed results instead of dropping them", () => {
    const [finding] = parseSarif(
      {
        version: "2.1.0",
        runs: [
          {
            tool: { driver: { name: "Example" } },
            results: [
              {
                ruleId: "R1",
                message: { text: "suppressed finding" },
                suppressions: [{ kind: "external" }],
              },
            ],
          },
        ],
      },
      context,
    );
    expect(finding.status).toBe("SUPPRESSED");
  });

  it("drops pass and notApplicable results", () => {
    const findings = parseSarif(
      {
        version: "2.1.0",
        runs: [
          {
            tool: { driver: { name: "Example" } },
            results: [
              { ruleId: "R1", kind: "pass", message: { text: "ok" } },
              { ruleId: "R2", kind: "notApplicable", message: { text: "n/a" } },
              { ruleId: "R3", kind: "fail", message: { text: "real finding" } },
            ],
          },
        ],
      },
      context,
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("R3");
  });

  it("uses partialFingerprints so identity survives line movement", () => {
    const first = parseSarif(semgrepSarif, context)[0];

    const shifted = structuredClone(semgrepSarif) as {
      runs: Array<{
        results: Array<{
          locations: Array<{ physicalLocation: { region: { startLine: number } } }>;
        }>;
      }>;
    };
    shifted.runs[0].results[0].locations[0].physicalLocation.region.startLine = 500;

    const afterShift = parseSarif(shifted, context)[0];
    expect(afterShift.fingerprint).toBe(first.fingerprint);
  });

  it("lets an adapter refine findings via the resolveCategory hook", () => {
    const findings = parseSarif(trivySarif, testContext("TRIVY"), {
      resolveCategory: (result) =>
        result.rule?.tags.some((tag) => /misconfig/i.test(tag))
          ? "IAC"
          : "CONTAINER",
    });

    expect(findings.map((finding) => finding.category)).toEqual([
      "CONTAINER",
      "IAC",
    ]);
  });

  it("applies a default severity only when nothing else resolves", () => {
    const [withLevel, withoutLevel] = parseSarif(
      checkovSarif,
      testContext("CHECKOV"),
      { category: "IAC", defaultSeverity: "MEDIUM" },
    );

    expect(withLevel.severity).toBe("HIGH"); // level: error
    expect(withoutLevel.severity).toBe("MEDIUM"); // no level at all
  });
});
