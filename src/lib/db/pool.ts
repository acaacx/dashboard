import { Pool, type PoolConfig, type QueryResultRow } from "pg";

/**
 * PostgreSQL connection pool.
 *
 * Cached on globalThis for the same reason the security container is: Next.js
 * dev-server hot reloads re-evaluate modules, and a fresh Pool per reload leaks
 * connections until Postgres refuses new ones.
 */

const POOL_KEY = Symbol.for("dashboard.db.pool");

type GlobalWithPool = typeof globalThis & { [POOL_KEY]?: Pool };

export function databaseUrl(): string | undefined {
  const url = process.env.DATABASE_URL?.trim();
  return url === "" ? undefined : url;
}

export function isPostgresConfigured(): boolean {
  return databaseUrl() !== undefined;
}

export function buildPoolConfig(url: string): PoolConfig {
  return {
    connectionString: url,
    // Modest ceiling: a dashboard is read-heavy and low-concurrency, and a
    // large pool on a serverless platform exhausts Postgres connection slots.
    max: Number(process.env.DATABASE_POOL_MAX ?? 10),
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    // Managed Postgres (Azure, Neon, Supabase, RDS) terminates plaintext
    // connections; honour sslmode from the URL and default to requiring TLS
    // unless the caller explicitly opted out or is on localhost.
    ssl: shouldUseSsl(url) ? { rejectUnauthorized: false } : undefined,
  };
}

function shouldUseSsl(url: string): boolean {
  if (/sslmode=disable/i.test(url)) return false;
  if (/sslmode=(require|verify-ca|verify-full)/i.test(url)) return true;
  try {
    const { hostname } = new URL(url);
    return hostname !== "localhost" && hostname !== "127.0.0.1";
  } catch {
    return false;
  }
}

export function getPool(): Pool {
  const url = databaseUrl();
  if (!url) {
    throw new Error(
      "DATABASE_URL is not set. Set SECURITY_STORAGE=memory to run without Postgres.",
    );
  }

  const globalRef = globalThis as GlobalWithPool;
  if (!globalRef[POOL_KEY]) {
    const pool = new Pool(buildPoolConfig(url));
    // An idle-client error (server restart, network blip) is emitted on the
    // pool; without a listener Node treats it as an unhandled 'error' event and
    // takes the process down.
    pool.on("error", () => {
      // Intentionally silent: pg discards the broken client and the next
      // query acquires a fresh one. Nothing here is safe to log verbatim.
    });
    globalRef[POOL_KEY] = pool;
  }
  return globalRef[POOL_KEY];
}

/** Run a parameterised query against the shared pool. */
export async function query<T extends QueryResultRow>(
  text: string,
  params: readonly unknown[] = [],
): Promise<T[]> {
  const result = await getPool().query<T>(text, params as unknown[]);
  return result.rows;
}

/** Close the pool. Used by tests and by graceful shutdown. */
export async function closePool(): Promise<void> {
  const globalRef = globalThis as GlobalWithPool;
  const pool = globalRef[POOL_KEY];
  if (pool) {
    delete globalRef[POOL_KEY];
    await pool.end();
  }
}
