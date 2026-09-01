# Handoff

_Updated 2026-09-01T18:47:00+08:00_

## Goal

Decision history — an append-only audit trail recording who changed a finding's
status, when, and why. **Shipped.** Follow-up doc/test corrections also shipped.

## Done

Everything. `main` @ `efcaa32`, in sync with `origin/main`.

**Decision history** (`a6e0057..031a583`, 8 commits, spec → plan → 6 code/doc):

- Migration: `finding_decisions` table, FK cascade, append-only
- Domain: `FindingDecision` type
- Repository: `recordDecision()` + `listDecisionHistory()`, both drivers
- Service: `setFindingStatus()` builds the decision, generates `dec_${uuid}`,
  writes atomically
- Route: `GET /api/security/findings/[id]/history` (401 / 200 / 404)
- Component: `FindingDetails` timeline — loading, error, empty, loaded

**Follow-ups since:**

- `356138f` — README and CLAUDE.md corrected. README's "Changing a finding's
  status" no longer claims "no user authentication"; auth shipped long ago.
- `efcaa32` — `tests/mock/seed-mock-data.test.ts` now asserts the seeded
  headline numbers (23 open / 3 critical / 7 high / 13 medium / 0 low) that the
  docs and demo screenshots quote. They used to drift silently.

**Gate re-verified 2026-09-01 at `efcaa32`** with `dashboard-test-pg` up and
`TEST_DATABASE_URL` exported:

- `npm run lint` — 0
- `npm run typecheck` — 0
- `npm test` — **518 passed / 39 files**
- `npm run build` — green

Decision history was also live-verified at ship time: seeded finding shows 1 row,
reopen + re-accept gives 3 newest-first; undecided findings show the empty state;
a viewer can read the timeline but not write.

## In Progress

Nothing. Working tree clean apart from this file, which the hook rewrites.

## Next step

None queued. The repo has no open work item — pick a feature and start.

## Decisions & Constraints

Do not relitigate:

- **Human decisions only.** Scanner ingestion paths never write history.
- The current-status snapshot stays on the finding. History is additive, so
  `Invariant 4` (`firstDetectedAt` / manual statuses / attribution fields) is
  untouched.
- **Drawer timeline only.** No audit page, and history is not in list payloads.
- **No backfill.** Findings decided before the feature show "Earlier decisions
  were not recorded."
- Append-only is enforced at the interface — no update or delete is exposed.
- **Retry-safe:** the service generates the id, Postgres does
  `ON CONFLICT (id) DO NOTHING`, so a retried write cannot duplicate a row.
- Viewers read history; `APPROVER` writes decisions.

## Traps

- **Test DB is port 5433.** 5432 on this machine is an SSH tunnel, not Postgres.
  Without `TEST_DATABASE_URL` you get 426 passed + 5 skipped, not 518.
- The findings-table fetch stub routes `/history` to `{ decisions: [] }` — test
  isolation, not a bug.
- Lint blocks a synchronous `setHistory` inside the effect. The timeline refetches
  on status change and keeps the old rows visible until the new ones land. That
  is deliberate.
- `vitest.config.mts` aliases `server-only` to a no-op. Without it no test can
  import the auth container or guards.
- The seeded headline numbers are now load-bearing. If
  `tests/mock/seed-mock-data.test.ts` fails, either restore the payload or update
  the docs and screenshots — do not just bless the new number.
- `npm run typecheck` runs `next typegen` first. Bare `tsc --noEmit` fails on
  `PageProps` / `LayoutProps`.

## Git

Branch `main` @ `efcaa32`, clean, in sync with `origin/main`.

```
efcaa32 test: assert the seeded dashboard's headline numbers
356138f docs: correct stale claims in README and CLAUDE.md
031a583 docs: document decision history
c8c2f12 feat: decision-history timeline in the finding drawer
76a8eed feat: viewer-readable decision history route
df085de feat: setFindingStatus records the decision and requires its author
bf178cb feat: postgres decision history — one transaction, replay-safe append
f99eaa8 feat: append-only decision history in the repository contract and memory driver
```
