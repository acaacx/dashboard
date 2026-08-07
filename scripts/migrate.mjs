#!/usr/bin/env node
/**
 * Minimal forward-only migration runner.
 *
 * Applies every .sql file in db/migrations in filename order, once, inside a
 * transaction, recording applied versions in schema_migrations. No ORM, no
 * codegen, no rollback machinery — the schema is small and forward-only, and a
 * migration tool that nobody understands is worse than 60 lines of SQL.
 *
 *   npm run db:migrate
 */

import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import pg from "pg";

const MIGRATIONS_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "db",
  "migrations",
);

/**
 * Connect with backoff. A database container that has accepted a TCP
 * connection is often still initialising, and CI would otherwise fail on a
 * race that resolves itself in a second.
 */
async function connectWithRetry(client, attempts = 10, delayMs = 500) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      await client.connect();
      return;
    } catch (error) {
      if (attempt >= attempts) throw error;
      console.log(
        `  waiting for database (attempt ${attempt}/${attempts}): ${error.message}`,
      );
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
}

async function main() {
  const connectionString = process.env.DATABASE_URL?.trim();
  if (!connectionString) {
    console.error(
      "DATABASE_URL is not set.\n" +
        "  export DATABASE_URL=postgres://user:pass@localhost:5432/dashboard",
    );
    process.exit(1);
  }

  const useSsl =
    !/sslmode=disable/i.test(connectionString) &&
    !/@(localhost|127\.0\.0\.1)[:/]/.test(connectionString);

  const client = new pg.Client({
    connectionString,
    ssl: useSsl ? { rejectUnauthorized: false } : undefined,
  });

  await connectWithRetry(client);

  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version    TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);

    const { rows } = await client.query("SELECT version FROM schema_migrations");
    const applied = new Set(rows.map((row) => row.version));

    const files = (await readdir(MIGRATIONS_DIR))
      .filter((name) => name.endsWith(".sql"))
      .sort();

    let count = 0;
    for (const file of files) {
      if (applied.has(file)) {
        console.log(`  skip  ${file} (already applied)`);
        continue;
      }

      const sql = await readFile(path.join(MIGRATIONS_DIR, file), "utf8");

      // Each migration is atomic: either the whole file lands and is recorded,
      // or nothing does. A half-applied schema is the worst outcome here.
      await client.query("BEGIN");
      try {
        await client.query(sql);
        await client.query(
          "INSERT INTO schema_migrations (version) VALUES ($1)",
          [file],
        );
        await client.query("COMMIT");
        console.log(`  apply ${file}`);
        count += 1;
      } catch (error) {
        await client.query("ROLLBACK");
        throw new Error(`Migration ${file} failed: ${error.message}`);
      }
    }

    console.log(
      count === 0
        ? "Schema already up to date."
        : `Applied ${count} migration${count === 1 ? "" : "s"}.`,
    );
  } finally {
    await client.end();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
