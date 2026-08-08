import { describe, expect, it } from "vitest";

import {
  burnDummyVerify,
  hashPassword,
  MIN_PASSWORD_LENGTH,
  verifyPassword,
} from "@/lib/auth/password";
import { WeakPasswordError } from "@/domain/auth/errors";

const GOOD = "correct horse battery staple";

describe("password hashing", () => {
  it("verifies a password against its own hash", async () => {
    const stored = await hashPassword(GOOD);
    await expect(verifyPassword(GOOD, stored)).resolves.toBe(true);
  });

  it("rejects the wrong password", async () => {
    const stored = await hashPassword(GOOD);
    await expect(verifyPassword("wrong horse battery staple", stored)).resolves.toBe(false);
  });

  it("produces a different hash each time, so salts are not reused", async () => {
    expect(await hashPassword(GOOD)).not.toBe(await hashPassword(GOOD));
  });

  it("is self-describing", async () => {
    const stored = await hashPassword(GOOD);
    expect(stored.split("$")).toHaveLength(6);
    expect(stored.startsWith("scrypt$")).toBe(true);
  });

  it("rejects a tampered hash rather than throwing", async () => {
    const stored = await hashPassword(GOOD);
    const parts = stored.split("$");
    parts[5] = Buffer.from("not the right key").toString("base64url");
    await expect(verifyPassword(GOOD, parts.join("$"))).resolves.toBe(false);
  });

  it("rejects an unrecognised algorithm rather than throwing", async () => {
    await expect(verifyPassword(GOOD, "bcrypt$10$salt$hash")).resolves.toBe(false);
  });

  it("rejects a malformed stored value rather than throwing", async () => {
    await expect(verifyPassword(GOOD, "")).resolves.toBe(false);
    await expect(verifyPassword(GOOD, "scrypt$notanumber$8$1$c2FsdA$aGFzaA")).resolves.toBe(false);
  });

  it("refuses a password under the minimum length", async () => {
    await expect(hashPassword("a".repeat(MIN_PASSWORD_LENGTH - 1))).rejects.toBeInstanceOf(
      WeakPasswordError,
    );
  });

  it("burns comparable work for an account that does not exist", async () => {
    await expect(burnDummyVerify("anything at all")).resolves.toBeUndefined();
  });
});
