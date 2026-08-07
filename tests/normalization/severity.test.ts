import { describe, expect, it } from "vitest";

import {
  firstKnownSeverity,
  normalizeSarifLevel,
  normalizeSecuritySeverity,
  normalizeSeverity,
  severityFromScore,
} from "@/lib/security/normalization/severity";

describe("normalizeSeverity", () => {
  it("maps each scanner's vocabulary onto the shared scale", () => {
    expect(normalizeSeverity("CRITICAL")).toBe("CRITICAL");
    expect(normalizeSeverity("critical")).toBe("CRITICAL");
    expect(normalizeSeverity("  High  ")).toBe("HIGH");
    // Semgrep
    expect(normalizeSeverity("ERROR")).toBe("HIGH");
    expect(normalizeSeverity("WARNING")).toBe("MEDIUM");
    expect(normalizeSeverity("INFO")).toBe("INFO");
    // Vendor synonyms
    expect(normalizeSeverity("moderate")).toBe("MEDIUM");
    expect(normalizeSeverity("blocker")).toBe("CRITICAL");
    expect(normalizeSeverity("minor")).toBe("LOW");
  });

  it("returns UNKNOWN rather than guessing for absent or junk input", () => {
    // Checkov community edition emits null; Gitleaks has no severity at all.
    expect(normalizeSeverity(null)).toBe("UNKNOWN");
    expect(normalizeSeverity(undefined)).toBe("UNKNOWN");
    expect(normalizeSeverity("")).toBe("UNKNOWN");
    expect(normalizeSeverity("   ")).toBe("UNKNOWN");
    expect(normalizeSeverity("banana")).toBe("UNKNOWN");
    expect(normalizeSeverity({})).toBe("UNKNOWN");
    expect(normalizeSeverity([])).toBe("UNKNOWN");
  });

  it("reads CVSS scores as numbers and as strings", () => {
    expect(normalizeSeverity(9.8)).toBe("CRITICAL");
    expect(normalizeSeverity(7.5)).toBe("HIGH");
    expect(normalizeSeverity("7.5")).toBe("HIGH");
    expect(normalizeSeverity(4.0)).toBe("MEDIUM");
    expect(normalizeSeverity(0.5)).toBe("LOW");
    expect(normalizeSeverity(0)).toBe("INFO");
  });
});

describe("severityFromScore", () => {
  it("uses the standard CVSS bands at their boundaries", () => {
    expect(severityFromScore(9.0)).toBe("CRITICAL");
    expect(severityFromScore(8.9)).toBe("HIGH");
    expect(severityFromScore(7.0)).toBe("HIGH");
    expect(severityFromScore(6.9)).toBe("MEDIUM");
    expect(severityFromScore(4.0)).toBe("MEDIUM");
    expect(severityFromScore(3.9)).toBe("LOW");
    expect(severityFromScore(0)).toBe("INFO");
  });

  it("does not invent a severity for a non-finite score", () => {
    expect(severityFromScore(Number.NaN)).toBe("UNKNOWN");
    expect(severityFromScore(Number.POSITIVE_INFINITY)).toBe("UNKNOWN");
    expect(severityFromScore(Number.NEGATIVE_INFINITY)).toBe("UNKNOWN");
  });
});

describe("normalizeSarifLevel", () => {
  it("maps the four SARIF levels", () => {
    expect(normalizeSarifLevel("error")).toBe("HIGH");
    expect(normalizeSarifLevel("warning")).toBe("MEDIUM");
    expect(normalizeSarifLevel("note")).toBe("LOW");
    expect(normalizeSarifLevel("none")).toBe("INFO");
  });

  it("does not promote SARIF `error` to CRITICAL", () => {
    // Otherwise every SARIF-producing tool would fill the critical bucket and
    // the number would stop meaning anything.
    expect(normalizeSarifLevel("error")).not.toBe("CRITICAL");
  });

  it("returns UNKNOWN for unrecognised levels", () => {
    expect(normalizeSarifLevel("catastrophe")).toBe("UNKNOWN");
    expect(normalizeSarifLevel(undefined)).toBe("UNKNOWN");
  });
});

describe("normalizeSecuritySeverity", () => {
  it("prefers a numeric security-severity over the coarse level", () => {
    expect(normalizeSecuritySeverity("9.1", "error")).toBe("CRITICAL");
    expect(normalizeSecuritySeverity(2.0, "error")).toBe("LOW");
  });

  it("falls back to the level when security-severity is absent or unusable", () => {
    expect(normalizeSecuritySeverity(undefined, "warning")).toBe("MEDIUM");
    expect(normalizeSecuritySeverity(null, "note")).toBe("LOW");
    expect(normalizeSecuritySeverity("not-a-number", "error")).toBe("HIGH");
  });
});

describe("firstKnownSeverity", () => {
  it("returns the first candidate that resolves", () => {
    expect(firstKnownSeverity(null, "", "HIGH", "LOW")).toBe("HIGH");
  });

  it("returns UNKNOWN when nothing resolves", () => {
    expect(firstKnownSeverity(null, undefined, "")).toBe("UNKNOWN");
  });
});
