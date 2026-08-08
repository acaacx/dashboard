import { execFile } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { verifyPassword } from "@/lib/auth/password";
import { createScopedTestPool, prepareSchema, TEST_DATABASE_URL } from "../helpers/postgres";

const run = promisify(execFile);

const SCRIPT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "scripts",
  "user.mjs",
);

const SCHEMA = "test_user_cli";
const PASSWORD = "correct horse battery staple";

async function cli(args: string[], env: Record<string, string> = {}) {
  return run("node", [SCRIPT, ...args], {
    env: {
      ...process.env,
      DATABASE_URL: `${TEST_DATABASE_URL}?options=-c%20search_path%3D${SCHEMA}`,
      SECURITY_STORAGE: "postgres",
      USER_CLI_PASSWORD: PASSWORD,
      ...env,
    },
  });
}

if (!TEST_DATABASE_URL) {
  describe.skip("user CLI", () => {
    it("skipped: TEST_DATABASE_URL is not set", () => {});
  });
} else {
  const pool = createScopedTestPool(SCHEMA);

  beforeAll(async () => {
    await prepareSchema(pool, SCHEMA);
  });

  afterAll(async () => {
    await pool.end();
  });

  describe("user CLI", () => {
    it("creates an account whose password verifies through the application", async () => {
      await cli(["create", "--email", "cli@example.com", "--role", "approver"]);

      const { rows } = await pool.query<{ password_hash: string; role: string }>(
        "SELECT password_hash, role FROM users WHERE email = $1",
        ["cli@example.com"],
      );

      expect(rows[0]?.role).toBe("APPROVER");
      // The CLI and the app must agree on the hash format, or provisioning
      // silently produces accounts nobody can sign in to.
      await expect(verifyPassword(PASSWORD, rows[0]!.password_hash)).resolves.toBe(true);
    });

    it("lists accounts", async () => {
      const { stdout } = await cli(["list"]);
      expect(stdout).toContain("cli@example.com");
      expect(stdout).not.toContain(PASSWORD);
      expect(stdout).not.toContain("scrypt$");
    });

    it("refuses a duplicate", async () => {
      await expect(cli(["create", "--email", "cli@example.com"])).rejects.toThrow();
    });

    it("refuses a short password", async () => {
      await expect(
        cli(["create", "--email", "short@example.com"], { USER_CLI_PASSWORD: "tooshort" }),
      ).rejects.toThrow();
    });

    it("changes a role", async () => {
      await cli(["role", "--email", "cli@example.com", "--role", "viewer"]);
      const { rows } = await pool.query<{ role: string }>(
        "SELECT role FROM users WHERE email = $1",
        ["cli@example.com"],
      );
      expect(rows[0]?.role).toBe("VIEWER");
    });

    it("deletes an account and its sessions", async () => {
      await pool.query(
        "INSERT INTO sessions (token_hash, user_id, expires_at) SELECT 'h', id, now() + interval '1 hour' FROM users WHERE email = $1",
        ["cli@example.com"],
      );

      await cli(["delete", "--email", "cli@example.com"]);

      const users = await pool.query("SELECT 1 FROM users WHERE email = $1", [
        "cli@example.com",
      ]);
      const sessions = await pool.query("SELECT 1 FROM sessions WHERE token_hash = 'h'");
      expect(users.rows).toHaveLength(0);
      expect(sessions.rows).toHaveLength(0);
    });

    it("refuses to run against the memory driver", async () => {
      await expect(
        run("node", [SCRIPT, "list"], {
          env: { ...process.env, DATABASE_URL: "", SECURITY_STORAGE: "memory" },
        }),
      ).rejects.toThrow();
    });
  });
}
