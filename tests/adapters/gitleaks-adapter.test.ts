import { describe, expect, it } from "vitest";

import {
  containsRawSecretFields,
  GITLEAKS_DEFAULT_SEVERITY,
  GitleaksAdapter,
  redactMatch,
} from "@/lib/security/adapters/gitleaks-adapter";
import { loadFixture, testContext } from "../helpers/fixtures";

const adapter = new GitleaksAdapter();
const nativeJson = loadFixture("gitleaks/result.json");
const sarif = loadFixture("gitleaks/result.sarif");
const context = testContext("GITLEAKS", { repositoryName: "payment-service" });

describe("GitleaksAdapter.canHandle", () => {
  it("claims the bare-array native format and its SARIF", () => {
    expect(adapter.canHandle(nativeJson)).toBe(true);
    expect(adapter.canHandle(sarif)).toBe(true);
  });

  it("does not claim other scanners or unrelated arrays", () => {
    expect(adapter.canHandle(loadFixture("semgrep/result.json"))).toBe(false);
    expect(adapter.canHandle(loadFixture("trivy/result.json"))).toBe(false);
    expect(adapter.canHandle([{ unrelated: true }])).toBe(false);
    expect(adapter.canHandle([])).toBe(false);
    expect(adapter.canHandle(null)).toBe(false);
  });
});

describe("GitleaksAdapter.parse", () => {
  it("normalizes leaks into SECRET findings", async () => {
    const findings = await adapter.parse(nativeJson, context);

    expect(findings).toHaveLength(2);
    expect(findings.every((finding) => finding.category === "SECRET")).toBe(true);
    expect(findings[0].title).toBe("Hardcoded AWS access key");
    expect(findings[0].ruleId).toBe("aws-access-token");
    expect(findings[0].file).toBe("deploy/legacy/aws.cfg");
    expect(findings[0].startLine).toBe(27);
  });

  it("treats a committed credential as CRITICAL by policy", async () => {
    const findings = await adapter.parse(nativeJson, context);
    expect(
      findings.every((finding) => finding.severity === GITLEAKS_DEFAULT_SEVERITY),
    ).toBe(true);
    expect(GITLEAKS_DEFAULT_SEVERITY).toBe("CRITICAL");
  });

  // The single most important behaviour in this adapter.
  it("never stores the secret value, the match, or the code context", async () => {
    const findings = await adapter.parse(nativeJson, context);
    const serialized = JSON.stringify(findings);

    expect(serialized).not.toContain("REDACTED-TEST-PLACEHOLDER-0001");
    expect(serialized).not.toContain("REDACTED-TEST-PLACEHOLDER-0002");
    expect(serialized).not.toContain("aws_access_key_id =");
    findings.forEach((finding) => {
      expect(containsRawSecretFields(finding)).toBe(false);
      expect(finding.metadata?.redacted).toBe(true);
    });
  });

  it("strips the description from SARIF, where the snippet embeds the secret", async () => {
    const findings = await adapter.parse(sarif, context);

    expect(findings).toHaveLength(1);
    expect(findings[0].description).toBeUndefined();
    expect(findings[0].severity).toBe("CRITICAL");
    expect(JSON.stringify(findings)).not.toContain("REDACTED-TEST-PLACEHOLDER-0001");
  });

  it("keeps non-reversible evidence for triage", async () => {
    const [finding] = await adapter.parse(nativeJson, context);
    expect(finding.metadata?.entropy).toBeCloseTo(3.8219);
    expect(finding.metadata?.commit).toBe(
      "9f1c4a2e7b3d5086af17c2d9e4b6a8130fc52947",
    );
  });

  it("uses the Gitleaks fingerprint as stable identity", async () => {
    const [original] = await adapter.parse(nativeJson, context);

    const moved = structuredClone(nativeJson) as Array<{ StartLine: number }>;
    moved[0].StartLine = 4242;

    const [afterMove] = await adapter.parse(moved, context);
    expect(afterMove.fingerprint).toBe(original.fingerprint);
  });

  it("skips entries that carry no usable identity", async () => {
    const findings = await adapter.parse([{}, null, 3, { RuleID: "r", File: "f" }], context);
    expect(findings).toHaveLength(1);
  });
});

describe("redactMatch", () => {
  it("returns a non-reversible descriptor", () => {
    const redacted = redactMatch("supersecretvalue");
    expect(redacted).toBeDefined();
    expect(redacted).not.toContain("supersecretvalue");
    expect(redacted).toContain("16 chars");
  });

  it("handles missing input", () => {
    expect(redactMatch(undefined)).toBeUndefined();
    expect(redactMatch("")).toBeUndefined();
    expect(redactMatch(42)).toBeUndefined();
  });
});
