import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Pool } from "pg";

/**
 * Test database helpers.
 *
 * Vitest runs test files in parallel. Two files pointed at the same database
 * would TRUNCATE each other's rows mid-test, so each file gets its own
 * PostgreSQL schema and a pool whose `search_path` is scoped to it. The files
 * stay independent without giving up parallelism.
 */

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL?.trim() || undefined;

const MIGRATION_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "db",
  "migrations",
);

/**
 * Every migration, in filename order — the same order `npm run db:migrate`
 * applies them. Reading the directory rather than naming one file means a new
 * migration reaches the test schemas without editing this helper.
 */
export function migrationSql(): string {
  return readdirSync(MIGRATION_DIR)
    .filter((name) => name.endsWith(".sql"))
    .sort()
    .map((name) => readFileSync(path.join(MIGRATION_DIR, name), "utf8"))
    .join("\n");
}

/**
 * Pool bound to a dedicated schema.
 *
 * Safe to build before the schema exists: `search_path` naming a missing schema
 * is not an error, and `CREATE SCHEMA` does not depend on it. Call
 * `prepareSchema` once before the first query.
 *
 * `schema` is a test-authored constant, never user input; it is validated
 * anyway because it is the one value that cannot be passed as a bind parameter.
 */
export function createScopedTestPool(schema: string): Pool {
  if (!TEST_DATABASE_URL) {
    throw new Error("TEST_DATABASE_URL is not set");
  }
  if (!/^[a-z_][a-z0-9_]*$/.test(schema)) {
    throw new Error(`Unsafe test schema name: ${schema}`);
  }

  return new Pool({
    connectionString: TEST_DATABASE_URL,
    max: 4,
    options: `-c search_path=${schema}`,
  });
}

/** Drop and recreate the schema, then apply the migration inside it. */
export async function prepareSchema(pool: Pool, schema: string): Promise<void> {
  await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await pool.query(`CREATE SCHEMA ${schema}`);
  await pool.query(migrationSql());
}
