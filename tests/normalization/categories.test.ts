import { describe, expect, it } from "vitest";

import {
  categoryFromTags,
  categoryFromTrivyClass,
  categoryFromTrivyMisconfigType,
  defaultCategoryForScanner,
} from "@/lib/security/normalization/categories";

describe("defaultCategoryForScanner", () => {
  it("assigns the documented category per single-purpose scanner", () => {
    expect(defaultCategoryForScanner("SEMGREP")).toBe("SAST");
    expect(defaultCategoryForScanner("CHECKOV")).toBe("IAC");
    expect(defaultCategoryForScanner("GITLEAKS")).toBe("SECRET");
    expect(defaultCategoryForScanner("UNKNOWN")).toBe("OTHER");
  });
});

describe("categoryFromTrivyClass", () => {
  it("splits one Trivy report across categories by result class", () => {
    // This is the case that makes per-scanner category mapping wrong: a single
    // Trivy run legitimately produces four different categories.
    expect(categoryFromTrivyClass("os-pkgs")).toBe("CONTAINER");
    expect(categoryFromTrivyClass("lang-pkgs")).toBe("SCA");
    expect(categoryFromTrivyClass("config")).toBe("IAC");
    expect(categoryFromTrivyClass("secret")).toBe("SECRET");
    expect(categoryFromTrivyClass("license")).toBe("CONFIGURATION");
  });

  it("is case-insensitive and falls back for unknown classes", () => {
    expect(categoryFromTrivyClass("OS-PKGS")).toBe("CONTAINER");
    expect(categoryFromTrivyClass("something-new")).toBe("SCA");
    expect(categoryFromTrivyClass(undefined, "OTHER")).toBe("OTHER");
  });
});

describe("categoryFromTrivyMisconfigType", () => {
  it("treats Dockerfile misconfigurations as container concerns", () => {
    expect(categoryFromTrivyMisconfigType("dockerfile")).toBe("CONTAINER");
    expect(categoryFromTrivyMisconfigType("Dockerfile")).toBe("CONTAINER");
  });

  it("treats every other IaC target as IAC", () => {
    expect(categoryFromTrivyMisconfigType("terraform")).toBe("IAC");
    expect(categoryFromTrivyMisconfigType("kubernetes")).toBe("IAC");
    expect(categoryFromTrivyMisconfigType("azure-arm")).toBe("IAC");
    expect(categoryFromTrivyMisconfigType(undefined)).toBe("IAC");
  });
});

describe("categoryFromTags", () => {
  it("classifies generic SARIF by rule tags", () => {
    expect(categoryFromTags(["security", "CWE-89", "injection"])).toBe("SAST");
    expect(categoryFromTags(["terraform", "azure"])).toBe("IAC");
    expect(categoryFromTags(["docker", "image"])).toBe("CONTAINER");
    expect(categoryFromTags(["dependency", "npm"])).toBe("SCA");
  });

  it("prefers SECRET when a result is tagged both security and secret", () => {
    expect(categoryFromTags(["security", "secret"])).toBe("SECRET");
  });

  it("falls back when there are no usable tags", () => {
    expect(categoryFromTags(undefined)).toBe("OTHER");
    expect(categoryFromTags([])).toBe("OTHER");
    expect(categoryFromTags([1, 2, 3])).toBe("OTHER");
    expect(categoryFromTags(["nothing-relevant"], "SAST")).toBe("SAST");
  });
});
