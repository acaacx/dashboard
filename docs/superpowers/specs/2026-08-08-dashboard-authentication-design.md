# Dashboard authentication and decision attribution

**Date:** 2026-08-08
**Status:** designed, not yet implemented

## Problem

Two entries in README "Known limitations" describe the same hole:

> Anyone who can reach the dashboard can change a finding's status. There is no
> user authentication, so decisions are recorded with a justification but no
> author.

The manual status control shipped on 2026-08-07 deliberately left `changedBy`
out, because inventing an author without an identity source would have
fabricated attribution. That was the right call then and it is the thing this
design removes the need for.

Two consequences follow from having no authentication at all:

1. Anyone who can reach the host can move a `CRITICAL` finding to
   `FALSE_POSITIVE`. A risk acceptance carries a justification but no signature,
   so it cannot be reviewed or attributed.
2. Every finding is readable anonymously through `GET /api/security/*`. The
   findings list names real vulnerabilities in real repositories — file paths,
   rule ids, CVEs. The list itself is sensitive, and the read API is a bypass
   around whatever the UI does.

## Scope

In scope:

- local user accounts with `scrypt` password hashing, no new dependency
- server-side sessions with real revocation
- `VIEWER` / `APPROVER` roles
- every dashboard page and read API behind a session
- `statusChangedBy` on `SecurityFinding`, recorded from the session
- a provisioning CLI
- two migrations, both repository drivers, one shared contract suite
- tests at every layer, including updating existing API route suites

Out of scope, deliberately:

- SSO, OIDC, or any external identity provider
- password reset, email delivery, account self-service
- an admin UI for user management — the CLI is the admin surface
- per-repository or per-application authorization scopes
- remember-me, sliding sessions, refresh tokens
- rate limiting on scan ingestion, which remains its own known limitation

## Delivery: two plans

This spec is implemented in two plans, so there is a working checkpoint in the
middle rather than one long stretch with the suite red. Migrating the existing
API route tests to a `withSession()` helper lands in the first plan, and it
touches every one of them.

**Plan 1 — the wall.** Accounts, sessions, login and logout, and every dashboard
page and read API behind a session. Provisioning CLI. Dev-account seeding for the
memory driver. Existing API suites migrated.

Checkpoint: nothing is reachable anonymously except the login page and scan
ingestion; the full verification gate passes.

**Plan 2 — roles and attribution.** `requireApprover`, role enforcement in the
status action, `statusChangedBy` through the domain, both drivers and both
`reconcileFinding` paths, and the viewer/approver UI in the drawer.

Checkpoint: a risk acceptance records who signed it, and a viewer cannot sign
one.

### The `role` column ships in plan 1, unenforced

`003_auth.sql` includes `role`, and `npm run user -- create` takes `--role`, even
though nothing reads it until plan 2.

The alternative — adding the column in a later migration — forces a backfill
decision for accounts that already exist, and both answers are bad: default
everyone to approver and the role split silently grants what it was built to
withhold, or default everyone to viewer and every existing account loses the
ability to act. Recording the intended role when the account is created avoids
the question entirely.

## Decisions taken

### Identity: local accounts, `scrypt` from `node:crypto`

Users live in a table this application owns. Passwords are hashed with `scrypt`
from `node:crypto`, so no authentication dependency enters a project whose
runtime dependencies are currently `next`, `react`, `react-dom`, `recharts`,
`pg`, `zod` and `server-only`.

The stored hash is self-describing — `scrypt$N$r$p$salt$hash` — so cost
parameters can be raised later without invalidating existing rows. Verification
reads the parameters out of the stored value rather than assuming today's
constants.

Rejected: OIDC against GitHub or Google. It removes password storage entirely
and would be the better answer for a deployed product, but it requires a
registered application and a client secret before anyone can log in at all,
which breaks the zero-setup local default this codebase protects everywhere
else.

Rejected: a single shared password in an environment variable, matching the
`SECURITY_INGEST_TOKEN` style. It gates the dashboard but yields no identity, so
`changedBy` would remain impossible — it solves the smaller half of the problem
and forecloses the larger half.

Rejected: trusting an identity header from an authenticating reverse proxy. It
is nearly free and correct behind Cloudflare Access or `oauth2-proxy`, and
catastrophically wrong the moment the app is reachable directly. The failure is
silent and total.

### Storage: both drivers, one contract suite

`UserRepository` and `SessionRepository` each get an in-memory and a PostgreSQL
implementation behind one interface, verified by a single shared contract suite
in the manner of `tests/repository/repository-contract.ts`.

This is the more expensive option and it is chosen because the alternative —
Postgres-only accounts — would mean the zero-setup default mode runs with no
authentication at all, which contradicts the fail-closed posture that
`requireIngestAuth` already establishes.

Emails are stored and compared lowercased, with uniqueness on the lowercased
value. The contract suite covers it, because a case-sensitive unique index would
let `Alice@example.com` and `alice@example.com` become two accounts.

### Sessions: opaque tokens, hashed at rest

A session is a row. The cookie carries 32 random bytes; the store holds only the
SHA-256 of that value, so a database dump yields no usable sessions — the same
reasoning that keeps scanner secrets out of the findings table.

Logout deletes the row, which makes revocation real: a copied cookie stops
working immediately, and a compromised session can be killed without logging
everyone out.

Lifetime is an absolute 12 hours with no sliding renewal. Predictable, and it
bounds the value of a stolen cookie. Expired rows are swept on lookup.

Rejected: a stateless HMAC-signed cookie. No storage and no contract suite, but
logout becomes advisory — a copied cookie stays valid until it expires, and the
only global revocation is rotating a secret that logs out every user. For a tool
whose purpose is handling security findings, "logout does not actually log you
out" is the wrong default.

There is no new secret to manage. Tokens are random and checked against stored
hashes, so nothing needs signing, rotating, or protecting in config.

### Cookie

`HttpOnly`, `SameSite=Lax`, `Secure` in production, `Path=/`, `Max-Age` matching
the session expiry. `SameSite=Lax` plus the origin checks Next.js applies to
Server Actions is the CSRF story; no separate token is introduced.

### Authorization: `VIEWER` and `APPROVER`

`VIEWER` reads the dashboard, including every justification already recorded.
`APPROVER` can change a finding's status.

This mirrors how the decision actually gets made: developers need to see their
findings without being able to dismiss them. `FindingDetails` receives a
`canDecide` boolean and shows a viewer a disabled control explaining that
approver role is required.

The action re-checks the role regardless of what the UI rendered, for the same
reason it already re-checks the manual-`RESOLVED` ban: a select element is not a
security boundary.

Rejected: no roles at all. Cheaper, and defensible given that provisioning is a
deliberate CLI act — but it would mean every account that can read a finding can
also accept its risk, which is precisely the separation a security dashboard
exists to maintain.

### Attribution: a denormalized email snapshot

`SecurityFinding` gains `statusChangedBy?: string`, holding the deciding user's
email as text at the moment of the decision.

A risk acceptance is an audit record and has to survive the person leaving.
Storing a foreign key forces a choice between `RESTRICT`, which means a departed
employee can never be deleted, and `SET NULL`, which silently erases attribution
from real risk acceptances. Neither is acceptable for an audit trail; a snapshot
avoids the question.

An email change does not retroactively rewrite historical records. For an audit
trail that is correct behavior, not a defect.

`statusChangedBy` must be threaded through `reconcileFinding` exactly as
`statusReason` is: **the merge path restores it from the stored finding, the NEW
path clears it.** Dropping the first line lets the next scan erase attribution;
dropping the second lets a scanner adapter plant one. Each direction gets a test,
matching the two that already cover `statusReason`.

### Enforcement: structural, not remembered

Next.js 16 renamed `middleware.ts` to `proxy.ts` and moved it to the Node.js
runtime by default, so a session could technically be validated there. The
framework's own documentation says not to rely on it:

> A matcher change or a refactor that moves a Server Function to a different
> route can silently remove Proxy coverage. Always verify authentication and
> authorization inside each Server Function rather than relying on Proxy alone.

Proxy also warns against depending on shared modules or globals, and this
application's container is cached on `globalThis` precisely so it survives hot
reloads.

So `proxy.ts` performs a cookie-presence redirect for navigation only — it
prevents a flash of the dashboard shell before the redirect — and carries a
comment stating in plain words that it is not a security boundary. Real
validation happens at every boundary:

| Boundary | Guard |
|---|---|
| `src/app/dashboard/layout.tsx` | `requireUser()` — redirects to `/login?next=…` |
| each of the four dashboard pages | `requireUser()` — returns the user |
| `GET /api/security/*` (4 routes) | `protectedRoute(handler)`, session injected |
| `POST /api/security/scans` | unchanged: `requireIngestAuth`, CI's token |
| `setFindingStatusAction` | `requireUser()` and `requireApprover()` in the action |

`protectedRoute` passes the resolved session into the handler as an argument, so
a handler cannot execute unauthenticated and omitting the wrapper is a type error
at the call site rather than a silent hole.

The per-page `requireUser()` is not redundant with the layout. Layouts do not
re-run on every client-side navigation, so the layout check is a redirect rather
than a gate. The page also genuinely needs the user in order to decide
`canDecide`, so the role-gated UI cannot render without having asked who is
looking.

Rejected: a convention plus a test that scans route files for a guard call. It
matches house style most closely and adds no abstraction, but it verifies that a
guard is *called*, not that its result is *honored*.

Rejected: a default-deny allowlist in proxy. Strongest against forgetting, but
the documentation above says proxy coverage of Server Functions cannot be relied
on, and an allowlist drifts.

Guards return `SessionUser { id, email, role }`. The `User` carrying
`passwordHash` never leaves the repository layer, so a hash cannot be serialized
to a client by accident. A test asserts it.

The `?next=` parameter is a redirect target supplied by whoever crafted the URL.
It is accepted only when it is a path beginning with a single `/` and not `//`,
and anything else falls back to `/dashboard`. Without that check, a login page is
an open redirect — the most convincing possible phishing link, because it really
does start on your domain. A test covers `//evil.example`, a scheme-qualified
URL, and a backslash variant.

### Provisioning: one CLI, no self-service

`npm run user -- create|list|role|delete`, alongside the existing
`npm run db:migrate`.

The password is prompted on stdin with echo disabled, never accepted as an argv
flag: argv is visible in `ps` and lands in shell history. Minimum 12 characters,
no composition rules. Duplicate emails are refused. `create` takes `--role`,
defaulting to `viewer`; `role` changes an existing account; `delete` removes one
and, through the FK cascade, all of its sessions.

`delete` exists because offboarding is the case the attribution decision above
was built around: removing a departed employee must not disturb the risk
acceptances they signed. It is also what makes the cascade behavior in the
contract suite reachable rather than theoretical.

Rejected: self-signup. On a dashboard listing exploitable vulnerabilities,
anyone who can reach the login page could grant themselves access.

Rejected: seeding an administrator from `SECURITY_ADMIN_EMAIL` and
`SECURITY_ADMIN_PASSWORD`. Zero-friction in a container, but it puts a real
password in the environment and makes rotation a config edit.

### Keeping zero setup working

The CLI is a separate process, so against the memory driver it writes to a store
the server cannot see. Without an answer, adding authentication would make
`npm run dev` unusable — locked out of the dashboard with no way to create an
account.

So in memory-driver mock mode the container seeds one dev approver and prints
its credentials to the server log. This is **refused outright when
`NODE_ENV=production`**, and a test asserts the refusal. It is the same shape as
the existing mock-data seeding, which the UI already labels as fabricated. The
CLI errors with a clear message when storage is memory.

The honest consequence belongs in README "Known limitations": with the memory
driver, accounts and sessions do not survive a restart. Authentication on the
memory driver is a development convenience; deployment means Postgres.

### Failure modes

Everything fails closed. If a session lookup exhausts the existing retry budget
against an unreachable database, the request is **denied**. An authentication
check that fails open during an outage is worse than none, because it looks like
one.

| Situation | Behavior |
|---|---|
| Wrong password or unknown email | Identical generic message and identical timing |
| Throttled | "Too many attempts, try again in N minutes" |
| Session expired mid-decision | Action returns `UNAUTHENTICATED`; drawer says so with a sign-in link |
| Viewer attempts a decision | `FORBIDDEN` from the action, whatever the UI rendered |
| No accounts exist | Login page says so and names the command to run |

Unknown emails are verified against a dummy hash so that a missing account and a
wrong password cost the same time. The throttle is keyed on the submitted email
whether or not it exists, so its message reveals nothing either.

Passwords and session tokens never reach a log line.

### Brute force

A fixed-window counter: 10 attempts per 15 minutes per email, then temporary
refusal. Small, and a password form without it is a standing invitation.

It lives on `SessionRepository` as `recordFailedAttempt(email)` and
`isThrottled(email)` rather than in a third repository — backed by the
`login_attempts` table under Postgres and a `Map` under the memory driver. One
consequence to accept knowingly: on the memory driver the counter resets when the
process restarts.

## Data model

Two forward-only migrations. Neither edits an applied file.

`003_auth.sql`

- `users` — `id` uuid PK, `email` text unique (lowercased), `password_hash` text,
  `role` text, `created_at` timestamptz
- `sessions` — `token_hash` text PK, `user_id` uuid FK `ON DELETE CASCADE`,
  `expires_at` timestamptz, `created_at` timestamptz, index on `expires_at`
- `login_attempts` — `email` text PK, `window_started_at` timestamptz, `count` int

`004_status_changed_by.sql`

- adds `status_changed_by` text to the findings table

`tests/helpers/postgres.ts` already reads every file in `db/migrations/`, so no
helper edit is needed.

## Components

```
src/domain/auth/          user.ts, session.ts, errors.ts   (pure types)
src/lib/auth/
  password.ts             scrypt hash + verify, dummy-hash path
  session.ts              token generation, cookie read/write, expiry
  guards.ts               requireUser, protectedRoute, requireApprover
  container.ts            composition root, reuses configuredStorage()
  repository/             user + session interfaces, memory + postgres
  services/auth-service.ts
src/app/login/            page + signInAction + signOutAction
src/proxy.ts              cookie-presence redirect, UX only
scripts/user.ts           create | list | role | delete
```

Auth gets its own composition root rather than joining
`src/lib/security/container.ts`, which seeds mock findings — authentication must
not depend on seeding. It reuses the exported `configuredStorage()` and the
shared pool, and follows the same `globalThis` caching and reset-seam pattern.

## Testing

Contract suite across both drivers: email uniqueness and case folding, lookup,
role change, session create/lookup/delete, expired sessions rejected, sessions
cascade-deleted with their user, throttle window opening and resetting.

Unit: scrypt round-trip, wrong password false, tampered hash false, unrecognized
parameter string rejected, dummy-hash path taken for unknown emails.

Guards: unauthenticated page redirects; expired cookie redirects and clears the
cookie; API without a session returns 401 leaking no detail; viewer forbidden;
approver allowed.

Regression tests for the specific ways this breaks:

- `reconcileFinding` merge path restores `statusChangedBy`; NEW path clears it
- the dev account seed is refused when `NODE_ENV=production`
- a session token never appears in a response body
- `SessionUser` carries no `passwordHash`

Component: viewer sees a disabled decision control with an explanation; approver
sees a working one.

CLI: creates a user, refuses a duplicate, refuses the memory driver, rejects a
password under 12 characters, and deletes a user without disturbing the
`statusChangedBy` already recorded on that user's decisions.

**Known cost, stated up front:** every existing test that exercises
`/api/security/*` fails the moment those routes require a session. They need a
`withSession()` helper and updating. That is real work in the plan, not a
footnote.

## Verification

```bash
npm run lint && npm run typecheck && npm test && npm run build
```

Run with `TEST_DATABASE_URL` set so the PostgreSQL suites run rather than skip.

Then a live pass in the dev server: sign in, decide a finding as an approver,
confirm the email is recorded and reads back through the API, confirm a viewer is
refused, confirm logout invalidates the session.

## Documentation

README gains an authentication section and loses the two "Known limitations"
entries this closes. It gains one: accounts and sessions do not survive a restart
on the memory driver.
