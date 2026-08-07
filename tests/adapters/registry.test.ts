import { describe, expect, it } from "vitest";

import { UnsupportedScannerError } from "@/domain/security/errors";
import { createDefaultAdapterRegistry } from "@/lib/security/adapters";
import { ScannerAdapterRegistry } from "@/lib/security/adapters/scanner-adapter";
import { loadFixture } from "../helpers/fixtures";

const registry = createDefaultAdapterRegistry();

describe("ScannerAdapterRegistry", () => {
  it("registers the four supported scanners", () => {
    expect(registry.supportedScanners().sort()).toEqual([
      "CHECKOV",
      "GITLEAKS",
      "SEMGREP",
      "TRIVY",
    ]);
  });

  it("resolves by declared scanner", () => {
    expect(
      registry.resolve(loadFixture("trivy/result.json"), "TRIVY").scanner,
    ).toBe("TRIVY");
  });

  it("resolves by sniffing when no scanner is declared", () => {
    expect(registry.resolve(loadFixture("semgrep/result.json")).scanner).toBe(
      "SEMGREP",
    );
    expect(registry.resolve(loadFixture("checkov/result.json")).scanner).toBe(
      "CHECKOV",
    );
    expect(registry.resolve(loadFixture("gitleaks/result.json")).scanner).toBe(
      "GITLEAKS",
    );
  });

  it("trusts the payload over a mislabelled declaration", () => {
    // A workflow labelled `trivy` that actually uploads Semgrep output should
    // still be normalized correctly rather than parsed by the wrong adapter.
    const adapter = registry.resolve(
      loadFixture("semgrep/result.json"),
      "TRIVY",
    );
    expect(adapter.scanner).toBe("SEMGREP");
  });

  it("falls back to the declared adapter when nothing claims the payload", () => {
    const adapter = registry.resolve({ totally: "unrecognised" }, "SEMGREP");
    expect(adapter.scanner).toBe("SEMGREP");
  });

  it("throws UnsupportedScannerError when nothing can handle the payload", () => {
    expect(() => registry.resolve({ totally: "unrecognised" })).toThrow(
      UnsupportedScannerError,
    );
    expect(() => registry.get("UNKNOWN")).toThrow(UnsupportedScannerError);
  });

  it("carries a machine-readable code on the error", () => {
    try {
      registry.get("UNKNOWN");
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(UnsupportedScannerError);
      expect((error as UnsupportedScannerError).code).toBe(
        "UNSUPPORTED_SCANNER",
      );
      expect((error as UnsupportedScannerError).toJSON()).toEqual({
        code: "UNSUPPORTED_SCANNER",
        message: expect.stringContaining("UNKNOWN"),
      });
    }
  });

  it("accepts a new adapter with no changes elsewhere", async () => {
    // This is the "adding a scanner" acceptance criterion in miniature: one
    // registration and a future scanner participates fully.
    const custom = new ScannerAdapterRegistry(registry.list());
    custom.register({
      scanner: "UNKNOWN",
      formats: ["json"],
      canHandle: (input) =>
        typeof input === "object" && input !== null && "futureScanner" in input,
      parse: async () => [],
    });

    expect(custom.resolve({ futureScanner: true }).scanner).toBe("UNKNOWN");
    // Existing routing is unaffected.
    expect(custom.resolve(loadFixture("trivy/result.json")).scanner).toBe("TRIVY");
  });
});
