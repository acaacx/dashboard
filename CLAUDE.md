@AGENTS.md

# DevSecOps Dashboard — working notes

Next.js 16 (App Router) · React 19 · TypeScript strict · Tailwind v4 · Recharts ·
Zod · Vitest · `pg`. Read `README.md` first — it is the real documentation and it
is kept current.

## What this is

Ingests security scanner output (Semgrep, Trivy, Checkov, Gitleaks), normalizes
it into one scanner-independent model, deduplicates it, tracks its lifecycle, and
displays it.

```
scanner output -> adapter -> SecurityFinding -> repository -> service -> API -> UI
```

## Invariants — do not break these

1. **Components never see scanner output.** They receive `SecurityFinding`
   objects and pre-computed statistics. Nothing in `src/components/` may parse a
   payload or infer severity/category.
2. **Adapters are the only vendor-aware code.** Adding a scanner = enum entry +
   adapter + fixtures + tests + one line in `createDefaultAdapterRegistry()`.
   **No UI change.** That is an acceptance criterion, not a preference.
3. **Secrets are never stored.** Gitleaks/Trivy secret findings drop `Secret`,
   `Match` and code context. A real leak was once found through the SARIF
   `message.text` field becoming the finding *title* — the guard lives in each
   adapter's `refine`, and tests assert it. Do not remove them.
4. **`firstDetectedAt` is never overwritten**, and `ACCEPTED_RISK` /
   `FALSE_POSITIVE` / `SUPPRESSED` are never auto-changed by a scan.
5. **Fingerprints exclude** timestamps, severity, status, description, commit and
   branch. Adding any of them silently duplicates every finding on every scan.
6. **No `dangerouslySetInnerHTML`.** Scanner text is untrusted. `sourceUrl` is
   scheme-checked before becoming a link.
7. **Metric definitions live in the service/repository**, never in a chart.

## Storage

Two drivers behind one interface, chosen in `src/lib/security/container.ts`:

- no `DATABASE_URL` → in-memory (default, zero setup)
- `DATABASE_URL` set → PostgreSQL (`SECURITY_STORAGE` forces either)

Both are verified by **the same contract suite**
(`tests/repository/repository-contract.ts`). If you touch either implementation,
that suite is the check that matters — it covers NULL filter handling, LIKE
escaping, page clamping, tiebreak ordering and MTTR-undefined-not-zero.

```bash
docker run -d --name dashboard-test-pg -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=dashboard_test -p 5433:5432 postgres:17-alpine
export TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test
npm test          # 323 tests; without the URL, 272 + 2 skipped
```

Migrations are forward-only SQL in `db/migrations/`, applied by
`npm run db:migrate`. Add a new numbered file; never edit an applied one.

Transient DB failures retry with jittered backoff (`src/lib/db/retry.ts`).
Permanent errors — constraint violations, syntax, undefined table — must keep
failing on the first attempt; if you widen `isRetryableDatabaseError`, you are
probably hiding a bug. Retry wraps whole operations, never a statement inside an
open transaction.

## Verify before claiming done

```bash
npm run lint && npm run typecheck && npm test && npm run build
```

## Traps

- **Port 5432 on this machine is an SSH tunnel, not a local Postgres.** Use 5433
  for local containers.
- **The container is cached on `globalThis`** so it survives HMR. Changes to
  seeding or container wiring need a dev-server restart, not just a save — a
  stale cache once made a fix look like it had failed.
- **`npm run typecheck` runs `next typegen` first.** Bare `tsc --noEmit` fails on
  `PageProps`/`LayoutProps` if route types were never generated.
- **Dashboard pages need `export const dynamic = "force-dynamic"`.** Without it
  Next prerenders them static and they serve build-time data forever.
- **Scan runs are anchored on `scannedAt`, not ingestion time** (`startedAt` vs
  `ingestedAt`). Conflating them made every scanner read "just now".
- **Component tests must wait for the expected query**, not read the last fetch
  call — filters are debounced 200 ms and two changes race under CPU load.
- **The secret-scan hook blocks credential-shaped literals**, including fake
  ones. Mock keys are assembled at runtime in `mock-scan-payloads.ts`.
- Mock data is tuned to hit exactly 23 open / 3 critical / 7 high / 13 medium /
  0 low. Changing the payloads changes those headline numbers.

## Not implemented on purpose

GitHub and Azure providers are stubs that report `isConfigured() === false`;
pages say "not connected" rather than showing invented data. Inventory
correlation is contracts-only (`src/domain/security/inventory.ts`) — ID-driven,
never fuzzy name matching. Do not add an inventory scanner here.

## State

Repo: https://github.com/acaacx/dashboard (public, `main`). Remote uses SSH;
git identity is set repo-locally.
