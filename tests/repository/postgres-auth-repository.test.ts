import { afterAll, beforeAll, describe, it } from "vitest";

import { PostgresSessionRepository } from "@/lib/auth/repository/postgres-session-repository";
import { PostgresUserRepository } from "@/lib/auth/repository/postgres-user-repository";
import { createScopedTestPool, prepareSchema, TEST_DATABASE_URL } from "../helpers/postgres";
import { runAuthRepositoryContract } from "./auth-repository-contract";

/**
 * The full auth contract against a real PostgreSQL database.
 *
 * Skipped unless TEST_DATABASE_URL is set. This file owns its schema and wipes
 * it freely, so never point TEST_DATABASE_URL at anything real.
 */

const SCHEMA = "test_auth_contract";

if (!TEST_DATABASE_URL) {
  describe.skip("auth repository contract: postgres", () => {
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

  runAuthRepositoryContract("postgres", {
    create: async () => {
      // Truncate rather than recreate: same isolation, far faster. CASCADE
      // because sessions reference users.
      await pool.query("TRUNCATE users, sessions, login_attempts CASCADE");
      return {
        users: new PostgresUserRepository(pool),
        sessions: new PostgresSessionRepository(pool),
      };
    },
  });
}
