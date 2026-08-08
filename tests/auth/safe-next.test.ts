import { describe, expect, it } from "vitest";

import { safeNextPath } from "@/lib/auth/safe-next";

describe("safeNextPath", () => {
  it("keeps an ordinary in-app path", () => {
    expect(safeNextPath("/dashboard/security")).toBe("/dashboard/security");
    expect(safeNextPath("/dashboard?severity=CRITICAL")).toBe("/dashboard?severity=CRITICAL");
  });

  it("falls back when absent or empty", () => {
    expect(safeNextPath(null)).toBe("/dashboard");
    expect(safeNextPath(undefined)).toBe("/dashboard");
    expect(safeNextPath("")).toBe("/dashboard");
  });

  // A login page that redirects anywhere is the most convincing phishing link
  // there is: it genuinely starts on your own domain.
  it("refuses a protocol-relative URL", () => {
    expect(safeNextPath("//evil.example/login")).toBe("/dashboard");
    expect(safeNextPath("/\\evil.example")).toBe("/dashboard");
  });

  it("refuses a scheme-qualified URL", () => {
    expect(safeNextPath("https://evil.example")).toBe("/dashboard");
    expect(safeNextPath("javascript:alert(1)")).toBe("/dashboard");
  });

  it("refuses a backslash variant", () => {
    expect(safeNextPath("\\\\evil.example")).toBe("/dashboard");
  });

  it("refuses anything not rooted at /", () => {
    expect(safeNextPath("dashboard")).toBe("/dashboard");
    expect(safeNextPath("../etc/passwd")).toBe("/dashboard");
  });
});
