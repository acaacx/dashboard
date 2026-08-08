import {
  randomBytes,
  scrypt,
  timingSafeEqual,
  type BinaryLike,
  type ScryptOptions,
} from "node:crypto";
import { promisify } from "node:util";

import { WeakPasswordError } from "@/domain/auth/errors";

/**
 * Password hashing with scrypt from node:crypto.
 *
 * No dependency is added for this. The stored value is self-describing —
 * `scrypt$N$r$p$salt$hash` — so the cost parameters can be raised later and old
 * rows still verify against the parameters they were written with.
 *
 * N is 16384 rather than a larger power of two on purpose: scrypt's memory use
 * is roughly N * r * 128 bytes, which at N=16384, r=8 is 16 MB. Node's default
 * `maxmem` is 32 MB, so N=32768 would throw at runtime unless every call also
 * passed a raised `maxmem`. Staying under the default keeps the failure mode
 * out of the codebase entirely.
 */

/**
 * `scrypt` has two overloads and no `__promisify__` declaration, so
 * `promisify` binds the first one — the one without an options argument. The
 * promisified signature is restated here, because the options argument is
 * exactly what this module exists to set.
 */
const scryptAsync = promisify(scrypt) as (
  password: BinaryLike,
  salt: BinaryLike,
  keylen: number,
  options: ScryptOptions,
) => Promise<Buffer>;

export const MIN_PASSWORD_LENGTH = 12;

const ALGORITHM = "scrypt";
const N = 16384;
const R = 8;
const P = 1;
const KEY_LENGTH = 64;
const SALT_LENGTH = 16;

async function derive(
  password: string,
  salt: Buffer,
  n: number,
  r: number,
  p: number,
): Promise<Buffer> {
  return scryptAsync(password, salt, KEY_LENGTH, { N: n, r, p });
}

export async function hashPassword(password: string): Promise<string> {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new WeakPasswordError(MIN_PASSWORD_LENGTH);
  }

  const salt = randomBytes(SALT_LENGTH);
  const key = await derive(password, salt, N, R, P);

  return [
    ALGORITHM,
    N,
    R,
    P,
    salt.toString("base64url"),
    key.toString("base64url"),
  ].join("$");
}

/**
 * Verify a password against a stored value.
 *
 * Returns false for anything it cannot make sense of rather than throwing. A
 * corrupt or foreign hash is a failed login, not a 500 — and a thrown error
 * here would distinguish "malformed row" from "wrong password" to a caller who
 * should learn neither.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 6) return false;

  const [algorithm, rawN, rawR, rawP, rawSalt, rawKey] = parts;
  if (algorithm !== ALGORITHM) return false;

  const n = Number(rawN);
  const r = Number(rawR);
  const p = Number(rawP);
  if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p)) return false;
  if (n <= 1 || r < 1 || p < 1) return false;

  try {
    const salt = Buffer.from(rawSalt!, "base64url");
    const expected = Buffer.from(rawKey!, "base64url");
    if (salt.length === 0 || expected.length === 0) return false;

    const actual = await scryptAsync(password, salt, expected.length, {
      N: n,
      r,
      p,
    });

    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

/**
 * A hash of a value nobody knows, used to spend comparable time when no account
 * matches the submitted email.
 *
 * Without this, a missing account returns far faster than a wrong password, and
 * the difference is a reliable account-enumeration oracle.
 */
const DUMMY_HASH_PROMISE = hashPassword(randomBytes(32).toString("base64url"));

export async function burnDummyVerify(password: string): Promise<void> {
  await verifyPassword(password, await DUMMY_HASH_PROMISE);
}
