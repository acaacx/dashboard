import { afterAll, beforeAll, describe, it } from "vitest";

import { PostgresSecurityFindingRepository } from "@/lib/security/repository/postgres-security-finding-repository";
import {
  createScopedTestPool,
  prepareSchema,
  TEST_DATABASE_URL,
} from "../helpers/postgres";
import { runSecurityFindingRepositoryContract } from "./repository-contract";

/**
 * Runs the full repository contract against a real PostgreSQL database.
 *
 * Skipped unless TEST_DATABASE_URL is set, so `npm test` works on a machine
 * with no database. CI and anyone touching the SQL should set it:
 *
 *   docker run -d --name dashboard-test-pg -e POSTGRES_PASSWORD=postgres \
 *     -e POSTGRES_DB=dashboard_test -p 5433:5432 postgres:17-alpine
 *   export TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test
 *   npm test
 *
 * This file owns its own schema and wipes it freely, so never point
 * TEST_DATABASE_URL at anything real.
 */

const SCHEMA = "test_repository_contract";

if (!TEST_DATABASE_URL) {
  describe.skip("SecurityFindingRepository contract: postgres", () => {
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

  runSecurityFindingRepositoryContract("postgres", {
    create: async () => {
      // Truncate rather than recreate the schema: same isolation, far faster.
      await pool.query("TRUNCATE security_findings");
      return new PostgresSecurityFindingRepository(pool);
    },
  });
}
