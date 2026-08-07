import { describe, expect, it } from "vitest";

import {
  CHECKOV_DEFAULT_SEVERITY,
  CheckovAdapter,
} from "@/lib/security/adapters/checkov-adapter";
import { loadFixture, testContext } from "../helpers/fixtures";

const adapter = new CheckovAdapter();
const nativeJson = loadFixture("checkov/result.json");
const sarif = loadFixture("checkov/result.sarif");
const context = testContext("CHECKOV", { repositoryName: "infrastructure" });

describe("CheckovAdapter.canHandle", () => {
  it("claims both Checkov envelope shapes", () => {
    expect(adapter.canHandle(nativeJson)).toBe(true);
    // Multi-framework runs emit an array of reports.
    expect(adapter.canHandle([nativeJson])).toBe(true);
    expect(adapter.canHandle(sarif)).toBe(true);
  });

  it("does not claim other scanners", () => {
    expect(adapter.canHandle(loadFixture("semgrep/result.json"))).toBe(false);
    expect(adapter.canHandle(loadFixture("trivy/result.json"))).toBe(false);
    expect(adapter.canHandle(loadFixture("gitleaks/result.json"))).toBe(false);
    expect(adapter.canHandle(undefined)).toBe(false);
  });
});

describe("CheckovAdapter.parse (native JSON)", () => {
  it("ingests failed checks only", async () => {
    const findings = await adapter.parse(nativeJson, context);

    // The fixture has one passed check and two failed ones.
    expect(findings).toHaveLength(2);
    expect(findings.every((finding) => finding.category === "IAC")).toBe(true);
    expect(findings.map((finding) => finding.ruleId)).toEqual([
      "CKV_AZURE_59",
      "CKV_AZURE_3",
    ]);
  });

  it("captures the offending resource address and line range", async () => {
    const [publicBlob] = await adapter.parse(nativeJson, context);

    expect(publicBlob.title).toBe(
      "Ensure that Azure Storage Account does not allow public blob access",
    );
    expect(publicBlob.resource).toBe("azurerm_storage_account.assets");
    expect(publicBlob.file).toBe("/azure/storage.tf");
    expect(publicBlob.startLine).toBe(14);
    expect(publicBlob.endLine).toBe(28);
    expect(publicBlob.sourceUrl).toBe(
      "https://docs.example.invalid/checkov/ckv-azure-59",
    );
  });

  it("honours a supplied severity and applies the documented default for null", async () => {
    const [withSeverity, withoutSeverity] = await adapter.parse(
      nativeJson,
      context,
    );
    expect(withSeverity.severity).toBe("HIGH");
    expect(withoutSeverity.severity).toBe(CHECKOV_DEFAULT_SEVERITY);
  });

  it("does not store the raw code block", async () => {
    const [finding] = await adapter.parse(nativeJson, context);
    expect(finding.metadata?.codeBlockOmitted).toBe(true);
    expect(JSON.stringify(finding)).not.toContain('resource "azurerm_storage_account"');
  });

  it("handles the array envelope", async () => {
    const findings = await adapter.parse([nativeJson, nativeJson], context);
    // Same two checks from each report; fingerprints collide by design and are
    // collapsed later by the ingestion service, not here.
    expect(findings).toHaveLength(4);
  });

  it("skips entries with neither an id nor a name", async () => {
    const findings = await adapter.parse(
      {
        check_type: "terraform",
        results: { failed_checks: [{}, null, { check_id: "CKV_X" }] },
      },
      context,
    );
    expect(findings).toHaveLength(1);
  });

  it("returns nothing when there are no results", async () => {
    expect(
      await adapter.parse({ check_type: "terraform", summary: {} }, context),
    ).toEqual([]);
  });
});

describe("CheckovAdapter.parse (SARIF)", () => {
  it("maps SARIF results to IAC with the default severity fallback", async () => {
    const findings = await adapter.parse(sarif, context);
    expect(findings).toHaveLength(2);
    expect(findings.every((finding) => finding.category === "IAC")).toBe(true);
    expect(findings[0].severity).toBe("HIGH");
    expect(findings[1].severity).toBe(CHECKOV_DEFAULT_SEVERITY);
  });
});
