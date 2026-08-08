import { describe, expect, it, afterAll, beforeAll } from "vitest";

import { createScopedTestPool, prepareSchema, TEST_DATABASE_URL } from "../helpers/postgres";

const SCHEMA = "test_auth_schema";

if (!TEST_DATABASE_URL) {
  describe.skip("auth schema", () => {
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

  describe("auth schema", () => {
    it("creates users, sessions and login_attempts", async () => {
      const { rows } = await pool.query<{ table_name: string }>(
        `SELECT table_name FROM information_schema.tables
         WHERE table_schema = $1 ORDER BY table_name`,
        [SCHEMA],
      );
      const names = rows.map((row) => row.table_name);
      expect(names).toContain("users");
      expect(names).toContain("sessions");
      expect(names).toContain("login_attempts");
    });

    it("rejects a duplicate email", async () => {
      await pool.query(
        `INSERT INTO users (id, email, password_hash, role) VALUES ($1,$2,$3,$4)`,
        ["usr_1", "dup@example.com", "hash", "VIEWER"],
      );
      await expect(
        pool.query(
          `INSERT INTO users (id, email, password_hash, role) VALUES ($1,$2,$3,$4)`,
          ["usr_2", "dup@example.com", "hash", "VIEWER"],
        ),
      ).rejects.toThrow();
    });

    it("deletes a user's sessions with the user", async () => {
      await pool.query(
        `INSERT INTO users (id, email, password_hash, role) VALUES ($1,$2,$3,$4)`,
        ["usr_3", "cascade@example.com", "hash", "APPROVER"],
      );
      await pool.query(
        `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1,$2,now())`,
        ["hash_3", "usr_3"],
      );

      await pool.query("DELETE FROM users WHERE id = $1", ["usr_3"]);

      const { rows } = await pool.query("SELECT 1 FROM sessions WHERE user_id = $1", [
        "usr_3",
      ]);
      expect(rows).toHaveLength(0);
    });
  });
}
