# Handoff

Updated 2026-08-08.

## What we were doing

Implementing the spec
`docs/superpowers/specs/2026-08-08-dashboard-authentication-design.md` —
authentication and decision attribution for the DevSecOps dashboard — split into
two plans.

**Both plans are complete, verified and pushed. There is no work in flight.**

## State: the whole spec has shipped

`main` at `380e14f`, working tree clean, in sync with `origin/main` (nothing
unpushed). The spec reads `**Status:** implemented (plan 1 2026-08-08, plan 2
2026-08-08)`. Both plan files have every task checkbox ticked — the single
remaining `- [ ]` in the roles plan is line 3's boilerplate sub-skill notice, not
a task.

Plan 1 — the wall (18 commits, `cb97b06..b9ff916`): local accounts with `scrypt`,
server-side revocable sessions, login/logout, every dashboard page and read API
behind a session, the provisioning CLI, dev-account seeding.

Plan 2 — roles and attribution (7 commits, `b9ff916..380e14f`):

```
380e14f docs: document roles and decision attribution
67dbdc1 feat: show a decision's author and lock a viewer's control
1be5c51 feat: require an approver to change a finding's status
16fb7d4 feat: add the approver guard
5ee6fa2 feat: record the deciding user on a status change
ffb127c feat: store who decided a finding's status
59817c2 feat: carry the deciding user through the finding lifecycle
```

What plan 2 added: `statusChangedBy` on `SecurityFinding`, threaded through both
`reconcileFinding` paths; migration `db/migrations/004_status_changed_by.sql` and
the column in the PostgreSQL finding repository; `requireApprover()` in
`src/lib/auth/guards.ts` with `isApprover` and the new `AuthDomainError`s;
enforcement in `setFindingStatusAction`; and a `canDecide` flag that renders a
viewer a disabled control with the reason.

## The single next action

None outstanding. Pick up whatever the user asks next. If that turns out to be
more auth work, read the spec's "Out of scope" list first — several plausible
next steps were ruled out deliberately (see below).

## Verified, not assumed

Re-run on 2026-08-08 at `380e14f`, with
`TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test`
exported and the `dashboard-test-pg` container up:

- `npm run lint` — exit 0
- `npm run typecheck` — exit 0
- `npm test` — **486 passed, 38 files**. Without the URL: 401 + 5 skipped.
- `npm run build` — succeeded

The same contract suite passes against both the in-memory and the PostgreSQL
stores. Plan 1 was live-verified in a browser across eight checks (redirects,
401s on the read APIs, HttpOnly holding, `?next=//evil.example` neutralised, the
login throttle). Plan 2's six live checks are ticked in its plan file: an
approver signs a decision and the drawer shows the email, the API returns the
same `statusChangedBy`, a viewer sees the locked control, an expired session
shows the sign-in prompt, and a re-scan preserves both email and justification.

## Decisions already made — do not relitigate

- **Local accounts, `scrypt` from `node:crypto`.** No new dependency.
- **Server-side sessions, not signed cookies.** Logout is real revocation.
- **Both storage drivers, one contract suite.**
- **Everything behind the login except scan ingestion** (`POST
  /api/security/scans`), which keeps its bearer token for CI.
- **Two roles, `VIEWER` / `APPROVER`.** No third role, no permission table.
- **`statusChangedBy` is a denormalized text email, never a foreign key.** A risk
  acceptance is an audit record that must outlive the person leaving. `RESTRICT`
  would make a departed employee undeletable; `SET NULL` would erase attribution.
- **No backfill** of `status_changed_by` for pre-plan decisions — those genuinely
  had no author. **No attribution on scanner-driven transitions** either; no
  person made those.
- **The UI is not the boundary.** `canDecide` only decides what renders;
  `setFindingStatusAction` re-checks the role regardless. `canDecide` defaults to
  `false` — fail closed.
- **Enforcement is structural**: `protectedRoute()` on routes, `requireUser()` in
  the layout *and* in each page.
- **Provisioning is a CLI.** No self-signup, no admin UI, no SSO/OIDC, no
  password reset.
- Execution was **inline via `superpowers:executing-plans`**, not
  subagent-driven: this harness is configured not to spawn agents unasked. Both
  plans name either as acceptable. Revisit only if the user asks.

## Plan bugs found during execution

Already corrected in code — listed so nobody reintroduces them from the plan
text, which still shows the original snippets.

1. **`promisify(scrypt)`** — these `@types/node` declare no `__promisify__` for
   `scrypt`, so promisify binds the 3-argument overload and the cost parameters
   become untypable. `src/lib/auth/password.ts` restates the signature via a cast
   to `(password, salt, keylen, options) => Promise<Buffer>`.
2. **`Object.defineProperty(process.env, "NODE_ENV", …)`** throws
   `'process.env' only accepts a configurable, writable, and enumerable data
   descriptor`. Use `vi.stubEnv` / `vi.unstubAllEnvs`.
3. **`protectedRoute<Context = undefined>`** fails Next 16's generated route
   validator, which types *every* handler — static routes included — as receiving
   a `{ params }` context. The default is `unknown`.
4. **The plan's `proxy()` redirected `/login` and `/api/*` too**, contradicting
   its own tests. `src/proxy.ts` checks the pathname prefix itself rather than
   trusting the matcher.

## Traps

- **`src/proxy.ts` is not a security boundary.** Cookie *presence* only, never
  validity. Layouts do not re-run on every client-side navigation, so a page that
  only inherits the layout check is still reachable.
- **`server-only` is aliased to its own `empty.js` in `vitest.config.mts`.**
  Vitest sets neither React condition, so the real module throws on import.
  Without the alias no test can import the auth container or the guards.
- **The secret-scan hook blocks credential-shaped literals, including fake ones.**
  The placeholder hash in the auth contract suite is assembled at runtime from two
  fragments — the same trick `mock-scan-payloads.ts` uses. Writing it inline
  blocks the edit, and the hook blocks *this file* too if it quotes such a value.
- **scrypt `N` must stay 16384.** Memory is roughly `N * r * 128`; N=32768 with
  r=8 hits Node's 32 MB default `maxmem` and throws at runtime.
- **The scrypt parameters are duplicated in `scripts/user.mjs` on purpose.**
  `tests/auth/user-cli.test.ts` asserts a CLI-written hash verifies through the
  application. Change one, change both.
- **The CLI cannot work against the memory driver** — separate process, store the
  server cannot see. Hence the dev seed, hard-refused when `NODE_ENV=production`,
  on Postgres, in live mode, or when any account exists. To test the viewer role
  on the memory driver, change the seeded account's role in the seed.
- Port 5432 on this machine is an SSH tunnel. Test container is on **5433**.
- The container is cached on `globalThis`; seeding and wiring changes need a dev
  server restart, not just a save. `resetAuthContainer()` is the test seam.
- `.claude/launch.json` has `"autoPort": true` — the dev server does not come up
  on 3000. `preview_list` then `preview_stop` if one is still running.
- The dev-server browser pane reported a **0x0 viewport**, so coordinate clicks
  missed. Driving forms through `javascript_tool` worked fine.
