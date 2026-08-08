# Handoff

Updated 2026-08-08.

## What we were doing

Designing and planning **dashboard authentication** — the next piece of work
after the manual finding status control shipped on 2026-08-07.

Two documents were written, reviewed and committed. **No implementation code
exists yet.** The next session executes plan 1.

## State: designed and planned, not started

`main` at `c0eb1f8`, working tree clean, in sync with origin.

Three commits this session, all documentation:

- `cec6a79` — the design spec
- `db2e092` — split into two plans
- `c0eb1f8` — plan 1 written

Read these two, in order:

1. `docs/superpowers/specs/2026-08-08-dashboard-authentication-design.md`
2. `docs/superpowers/plans/2026-08-08-dashboard-authentication-wall.md`

## The single next action

Execute plan 1, Task 1, using **superpowers:subagent-driven-development** — the
user chose subagent-driven execution over inline. A fresh subagent per task,
review between tasks.

The plan is 13 TDD tasks. Task 1 is the migration plus the auth domain types.

## Verified, not assumed

- Full gate passed on `main` before any of this started:
  `npm run lint && npm run typecheck && npm test && npm run build` — clean.
  **349 tests with `TEST_DATABASE_URL` set**, 24 files.
- Test Postgres container was up on **5433** and the Postgres suites ran rather
  than skipped.
- Next 16 docs were read from `node_modules/next/dist/docs/`, not recalled:
  `middleware.ts` is deprecated and renamed to `proxy.ts`, and Proxy defaults to
  the Node runtime.

## Decisions already made — do not relitigate

- **Local accounts with `scrypt` from `node:crypto`.** No new dependency. OIDC,
  a shared password, and trusting a proxy header were all considered and
  rejected, with reasons recorded in the spec.
- **Server-side sessions, not signed cookies.** Logout must be real revocation.
- **Both storage drivers, one contract suite** — memory and Postgres, matching
  `SecurityFindingRepository`.
- **Everything behind the login except scan ingestion**, which keeps its bearer
  token for CI.
- **`VIEWER` / `APPROVER` roles**, but the column ships in plan 1 *unenforced*.
  Adding it later would force a backfill default and both options are wrong.
- **`statusChangedBy` is a denormalized email snapshot**, so deleting a departed
  employee never blanks out their risk acceptances. Plan 2, not plan 1.
- **Enforcement is structural**: `protectedRoute()` injects the session,
  `requireUser()` runs in the layout *and* in each page.
- **Provisioning is a CLI**, no self-signup, no admin UI.

## Traps

- **`src/proxy.ts` is not a security boundary.** It checks only that a cookie is
  present. Next's own docs warn that a matcher change silently drops Server
  Function coverage, so every boundary validates for itself. A page that only
  inherits the layout check is still reachable by client-side navigation —
  layouts do not re-run on every navigation.
- **scrypt `N` must stay 16384.** Memory is roughly `N * r * 128`; N=32768 with
  r=8 hits Node's 32 MB default `maxmem` and throws at runtime.
- **The scrypt parameters are duplicated in `scripts/user.mjs` on purpose.** The
  CLI runs outside TypeScript and cannot import the app module. A test asserts a
  CLI-written hash verifies through the application — without it, provisioning
  silently creates accounts nobody can sign in to.
- **The four `/api/security/*` route handlers have no tests today.** Nothing
  under `tests/` imports one; the component suites stub global `fetch`. The spec
  originally claimed existing suites would need migrating — that was wrong and
  is corrected. Plan 1 writes the first route tests instead.
- **The CLI cannot work against the memory driver.** It is a separate process
  writing to a store the server cannot see. Hence the dev-account seed, which is
  hard-refused when `NODE_ENV=production`.
- Port 5432 on this machine is an SSH tunnel. Test container is on **5433**.
- The container is cached on `globalThis`; seeding and wiring changes need a dev
  server restart, not just a save.
- `.claude/launch.json` has `"autoPort": true`. A dev server from an earlier
  session may still be running — `preview_list` then `preview_stop`.
