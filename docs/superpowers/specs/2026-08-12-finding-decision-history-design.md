# Finding decision history

**Date:** 2026-08-12
**Status:** designed

## Problem

A finding records one decision: `statusReason`, `statusChangedAt` and
`statusChangedBy` describe the state it is in now and who put it there. The
previous decision is overwritten.

That is enough to answer "who accepted this risk?" and not enough to answer any
of the questions an audit actually asks:

1. A `CRITICAL` finding is `FALSE_POSITIVE`. It was `ACCEPTED_RISK` last month
   under a different justification, signed by someone else. Nothing in the
   system says so.
2. A finding cycles `OPEN → ACCEPTED_RISK → OPEN → ACCEPTED_RISK`. The row shows
   one acceptance. Repeated acceptance and reopening is exactly the pattern a
   reviewer wants to see, and it is invisible.
3. An approver leaves. Their name survives on the findings they touched last,
   and vanishes from every finding someone has since re-decided.

The columns are a snapshot. This design adds the tape.

## Scope

In scope:

- a `FindingDecision` domain type and an append-only `finding_decisions` table
- `recordDecision` and `listDecisionHistory` on `SecurityFindingRepository`,
  both drivers, one shared contract suite
- `setFindingStatus` writing the finding and its decision in one atomic call
- `GET /api/security/findings/:id/history`, readable by any signed-in user
- a timeline in the finding drawer

Out of scope, deliberately:

- a backfill of decisions taken before this ships
- an audit page, an export, or history in any list payload
- history for scanner-driven transitions
- editing or deleting a recorded decision
- retention, archival, or a purge command

## Decisions taken

### Human decisions only

`recordDecision` is called from exactly one place: `setFindingStatus`, which is
reached only through `setFindingStatusAction` behind `requireApprover()`.

Scanner-driven transitions record nothing. `reconcileFinding` reopening a
finding and `resolveFinding` closing one are state derived from evidence, not
decisions made by a person, and writing them into an attributed audit trail
would mean either inventing an author or storing rows whose author column is
empty. Both corrupt the meaning of the table.

The consequence to accept knowingly: the history explains every human decision
and none of the machine transitions between them. A row reading
`OPEN → ACCEPTED_RISK` may sit above an earlier `ACCEPTED_RISK` with no visible
account of how the finding returned to `OPEN`. `firstDetectedAt`, `resolvedAt`
and the trend data already describe the machine's side.

### Alongside the existing columns, not replacing them

`statusReason`, `statusChangedAt` and `statusChangedBy` stay exactly as they
are. History is additive.

Invariant 4 in CLAUDE.md and both `reconcileFinding` paths are untouched. The
finding row remains the current-decision snapshot that the list, the drawer
header and every existing test read; nothing has to join a second table to
render a findings page.

Rejected: deriving the current decision from the newest history row and dropping
the columns. It removes the duplication, and it makes every findings query a
join or a correlated subquery against a table that grows without bound, to
recompute a value that has one correct answer already stored. It would also
rewrite the merge path, which is the most dangerous code in the repository.

### Approach: one repository method, one transaction

`SecurityFindingRepository` gains two methods and no more:

```ts
recordDecision(
  id: string,
  patch: Partial<SecurityFinding>,
  decision: FindingDecision,
): Promise<SecurityFinding | null>;

listDecisionHistory(id: string): Promise<FindingDecision[]>;
```

`recordDecision` applies the patch and appends the row in one driver call.
Postgres does it inside a single `BEGIN` / `COMMIT`; the memory driver mutates
both structures in one synchronous block. Either both land or neither does.

There is no `updateDecision` and no `deleteDecision` in either driver.
Append-only is a property of the interface, not a convention someone has to
remember.

Rejected: a separate `FindingDecisionRepository` orchestrated by the service.
It is the cleaner separation, and it makes the write two independently-retried
operations — so a crash between them leaves a decision with no history row.
That gap is the precise failure this feature exists to close.

Rejected: adding `withTransaction` to the Postgres container so the service can
compose the two calls. It is machinery built for one call site, and it puts
repository calls inside an open transaction — the shape `withRetry` must never
wrap, because retrying a statement inside a transaction that has already failed
retries nothing useful.

### Retry idempotency: the service generates the id

`saveMany` replays safely under `withRetry` because its insert is an upsert. An
append is not.

`08007 transaction_resolution_unknown` is retryable, and it means precisely that
the outcome is unknown — a lost `COMMIT` acknowledgement can replay a
transaction that in fact committed. A driver-generated decision id would produce
a second row for the same decision.

So the service generates the id — `dec_${randomUUID()}`, matching the existing
`run_` and `usr_` prefixes — and the insert is `ON CONFLICT (id) DO NOTHING`.
The replay is then a no-op, and the contract suite asserts it directly rather
than trusting the reasoning.

### `changedBy` becomes required

`setFindingStatus` takes `options.changedBy?: string` today. It becomes
required.

`decided_by` is `NOT NULL`, and the only caller that omits it is
`src/lib/security/mock/seed-mock-data.ts`, which will pass `dev@localhost` —
the same account the memory-driver seed already creates. That value is a text
snapshot, so it stores cleanly on Postgres, where no such account exists.

Making it required means a future caller cannot silently record an unattributed
decision; the type rejects it at the call site.

### No backfill

Findings decided before this ships have a `statusChangedBy` and no history. They
get an explicit line — "Earlier decisions were not recorded." — not a
synthesized row.

A synthesized row would be indistinguishable from a real one while asserting a
`fromStatus` nobody recorded. An audit trail that fabricates its earliest entry
is worse than one that admits where it begins.

### Read access: any signed-in user

`GET /api/security/findings/:id/history` requires a session and no role. A
viewer who can already read a finding's current justification can read its
previous ones. `requireApprover()` guards writing decisions, not reading them —
the point of the role split is that developers see their findings without being
able to dismiss them.

## Data model

New domain type in `src/domain/security/decision.ts`:

```ts
export interface FindingDecision {
  id: string;
  findingId: string;
  fromStatus: FindingStatus;
  toStatus: FindingStatus;
  reason?: string;
  decidedBy: string;
  decidedAt: string;
}
```

One forward-only migration, `005_finding_decisions.sql`:

```sql
CREATE TABLE IF NOT EXISTS finding_decisions (
  id          TEXT PRIMARY KEY,
  finding_id  TEXT NOT NULL REFERENCES security_findings (id) ON DELETE CASCADE,
  from_status TEXT NOT NULL,
  to_status   TEXT NOT NULL,
  reason      TEXT,
  decided_by  TEXT NOT NULL,
  decided_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS finding_decisions_finding_idx
  ON finding_decisions (finding_id, decided_at DESC);
```

- **This table takes a foreign key, unlike `status_changed_by`.** That column
  refused one because users are deleted and attribution has to survive them.
  Findings are never deleted — the repository interface has no delete method —
  so the FK costs nothing. `ON DELETE CASCADE` states the correct behavior for a
  path that is not exercised.
- `finding_id` references `security_findings(id)`, not `fingerprint`. `id` is
  unique and the merge path pins `id: existing.id`, so it is stable across
  re-ingestion.
- `decided_by` is `NOT NULL`: `requireApprover()` guarantees a session, so a row
  without an author is a bug, and the schema should say so rather than accept it.
- `reason` is nullable only because reopening to `OPEN` permits it.
- `from_status` always differs from `to_status`, because `setFindingStatus`
  returns early on a no-op transition.

`tests/helpers/postgres.ts` reads every file in `db/migrations/`, so no helper
edit is needed.

## Components

```
src/domain/security/decision.ts          FindingDecision (pure type)
src/lib/security/repository/
  security-finding-repository.ts         + recordDecision, listDecisionHistory
  memory-security-finding-repository.ts  one synchronous block
  postgres-security-finding-repository.ts  BEGIN / upsert / insert / COMMIT
src/lib/security/services/security-service.ts  builds the decision, generates id
src/app/api/security/findings/[id]/history/route.ts
src/components/security/finding-details.tsx    timeline section
db/migrations/005_finding_decisions.sql
```

### Write path

`setFindingStatus` keeps its current order — no-op check, `canTransition`,
reason validation — and only then builds the decision from the transition it has
already computed, calling `recordDecision` where it currently calls `update`.

Nothing about its error behavior changes. A rejected transition or an invalid
justification throws before the decision object exists, so a refusal writes no
history: rejections are not decisions.

The NEW path in `reconcileFinding` clearing `statusChangedBy` cannot orphan
history. NEW means an unseen fingerprint, therefore a new finding id, therefore
no rows to orphan.

### Read path and UI

`listDecisionHistory` returns newest first, ordered `decided_at DESC, id DESC`
so equal timestamps still order deterministically — the same tiebreak discipline
the contract suite already applies to `findAll`.

The route mirrors its sibling `GET /api/security/findings/:id`:
`protectedRoute<{ params: Promise<{ id: string }> }>`, `{ decisions }` on
success, 404 when the finding is absent — so the two endpoints leak existence
identically.

`FindingDetails` gains an optional
`loadHistory?: (id: string) => Promise<FindingDecision[]>` prop, injected the
way `onApplyStatus` already is. Absent means no timeline, failing closed like
`canDecide`. This keeps `fetch` out of the component and lets tests await the
expected call rather than race it.

Three states: loading, empty, list. The empty state reads "Earlier decisions
were not recorded." — the visible consequence of the no-backfill decision.

Each row renders as `alice@example.com moved OPEN → ACCEPTED_RISK`, the
timestamp through `formatDateTime`, and the justification below as text. JSX
escaping only. The `dangerouslySetInnerHTML` ban is absolute here even though
the reason is human input rather than scanner output.

After a successful decision the drawer refetches rather than optimistically
prepending, so what is displayed is what was stored.

## Failure modes

| Situation | Behavior |
|---|---|
| Finding absent | `recordDecision` returns `null`, no decision row written |
| Invalid transition or invalid reason | Throws before any write; no history |
| No-op transition | Returns early; no history |
| Database failure during the append | Whole decision fails; drawer shows its existing inline error |
| History fetch fails in the drawer | Inline line in the timeline; the form stays usable |
| Unexpected error in the route | `errorToResponse` returns an opaque `INTERNAL_ERROR` |

Postgres returns `null` for an absent finding because the finding `UPDATE`
affects zero rows, which rolls the transaction back; the memory driver checks
the id before either mutation. A decision row can never exist for a finding that
was never patched, and a patched finding can never lack its row.

Because the append shares a transaction with the finding update, there is no
partial-success state for the UI to render. A storage failure fails the decision
outright, which is what the drawer already knows how to report.

## Security

The trail adds no new input surface. `reason` is the value
`statusReasonSchema` has already validated on its way to the finding row, not a
second path into storage.

No error message quotes a justification, an email, or a stored row.
`errorToResponse` stays opaque for anything that is not a domain error, and the
append introduces no new domain error.

Rendering is JSX escaping only, per invariant 6. Append-only is enforced by the
absence of mutating methods rather than by review.

## Testing

Contract suite (`tests/repository/repository-contract.ts`, both drivers):

- `recordDecision` applies the patch and appends the row
- an unknown id returns `null` **and leaves history empty** — the atomicity
  assertion
- `listDecisionHistory` returns newest first, with a deterministic tiebreak for
  equal `decidedAt`
- the same decision id recorded twice yields one row — the retry-replay case
- an absent history returns `[]`
- a NULL `reason` round-trips as `undefined`, not `""`

Service:

- `fromStatus` is the finding's status before the change
- a no-op transition, an invalid transition and an invalid justification each
  write nothing
- `reconcileFinding` and `resolveFinding` leave history empty — "human decisions
  only" as an assertion rather than a comment

Route, in `tests/api/protected-routes.test.ts`: 401 unauthenticated; **200 for a
viewer**, stated explicitly because it is the deliberate asymmetry with the
write path; 404 for an unknown id.

Component, in `tests/components/finding-details.test.tsx`: loading, empty and
populated timelines; no timeline when `loadHistory` is absent; a refetch after a
successful decision; an inline error when `loadHistory` rejects. Tests await the
expected call rather than reading the last one.

## Verification

```bash
npm run lint && npm run typecheck && npm test && npm run build
```

Run with `TEST_DATABASE_URL` set so the PostgreSQL suites run rather than skip,
after `npm run db:migrate` has applied `005`.

Then a live pass in the dev server: accept a risk as an approver, reopen it,
accept it again, and confirm the drawer shows three rows newest-first with the
right authors and justifications; confirm a viewer can read the timeline and
cannot add to it; confirm a finding decided before the migration shows the
"Earlier decisions were not recorded." line.

The mock seed passing `dev@localhost` adds one history row in dev mode and does
not change the headline numbers — 23 open, 3 critical, 7 high, 13 medium, 0 low.

## Documentation

README gains a decision-history subsection under the finding lifecycle, stating
what is recorded, what is not (scanner transitions), and that decisions taken
before this shipped were not backfilled.
