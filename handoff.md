# Handoff

Updated 2026-08-12.

## What we were doing

Brainstorming a spec for **decision history** — an append-only audit trail of who
changed a finding's status, when, and why. Running
`superpowers:brainstorming`, currently at checklist step 5 (present the design).

**Nothing is implemented. No spec file exists yet.** The design has been agreed
in conversation and is recorded in full below so it does not have to be
rediscovered.

## State: auth shipped, decision history designed but not written down

`main` at `c876a42`, working tree clean, in sync with `origin/main`.

The whole authentication spec has shipped across two plans (wall, then roles and
attribution). Gate re-verified at `380e14f` on 2026-08-12: lint 0, typecheck 0,
**486 tests / 38 files**, build green, with
`TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test`
and the `dashboard-test-pg` container up.

## The single next action

Present **section 4 of the design — errors, security and testing** — get
approval, then write the spec to
`docs/superpowers/specs/2026-08-12-finding-decision-history-design.md`, matching
the format of the two existing specs. Then self-review it, ask the user to review
it, and only then invoke `superpowers:writing-plans`.

Sections 1–3 are already approved. Do not re-present them.

## The design, as agreed

Four questions were asked and answered. **Do not reopen these.**

1. **Human decisions only.** Scanner-driven transitions (auto-resolve,
   reopen-by-scan) record nothing. No person made those.
2. **Alongside — the columns stay.** `statusReason` / `statusChangedAt` /
   `statusChangedBy` remain the current-decision snapshot on the finding row.
   History is additive. Invariant 4 and `reconcileFinding` are untouched.
3. **Drawer timeline only.** No audit page, no history embedded in list payloads.
4. **No backfill.** Findings decided before this ships get an explicit
   "Earlier decisions were not recorded." line, not a synthesized row.

Approach **B** was chosen over two alternatives: a `recordDecision()` method on
`SecurityFindingRepository` that writes both the finding and the history row
atomically inside one driver call. Rejected: a separate history repository
orchestrated by the service (two independently-retried operations, so a crash
between them leaves a decision with no history row — the exact gap this
feature exists to close), and adding `withTransaction` to the Postgres container
(machinery for one call site, and it puts repository calls inside an open
transaction, the shape retry must never wrap).

### Section 1 — data model (approved)

New domain type `FindingDecision` in `src/domain/security/decision.ts`:
`{ id, findingId, fromStatus, toStatus, reason?, decidedBy, decidedAt }`.

Migration `005_finding_decisions.sql`:

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

- **This table gets a foreign key**, unlike `status_changed_by`. That column
  refused one because users get deleted and attribution must survive them.
  Findings are never deleted — the repository interface has no delete method —
  so the FK is free. `CASCADE` is stated for correctness, not exercised.
- `finding_id` targets `security_findings(id)`, not `fingerprint`: `id` is
  `UNIQUE`, and the merge path pins `id: existing.id`, so it is stable across
  re-ingestion.
- `decided_by` is `NOT NULL` — `requireApprover()` guarantees a session, so a
  row without an author is a bug and the schema says so.
- `reason` is nullable only because reopening to `OPEN` allows it.
- `from_status` is `NOT NULL` and always differs from `to_status`, because
  `setFindingStatus` returns early on a no-op transition.

### Section 2 — write path (approved)

`SecurityFindingRepository` gains exactly two methods:

```ts
recordDecision(id, patch, decision): Promise<SecurityFinding | null>
listDecisionHistory(id): Promise<FindingDecision[]>
```

No update, no delete for decisions in either driver — append-only is a property
of the interface, not a convention.

- **Postgres** follows the `saveMany` pattern: `withRetry(() =>
  this.recordDecisionOnce(...))`, one `BEGIN`, finding upsert plus decision
  insert, `COMMIT`, rollback and release on error. Retry still wraps the whole
  unit from `BEGIN`. The memory driver mutates both structures in one
  synchronous block.
- **Retry idempotency — the subtle part.** `saveMany` replays safely because its
  insert is an upsert; an append is not. `08007
  transaction_resolution_unknown` is retryable, so a lost `COMMIT`
  acknowledgement could replay a transaction that actually committed. Therefore
  **the service generates the decision id** (`dec_${randomUUID()}`, matching
  `run_` and `usr_`) and the insert is `ON CONFLICT (id) DO NOTHING`. A
  driver-generated id would produce a duplicate row on replay.
- **`setFindingStatus` keeps its current order** — no-op check, `canTransition`,
  reason validation — then builds the decision from the transition it already
  computed and calls `recordDecision` instead of `update`.
- **`changedBy` becomes required**, not optional. The only caller that omits it
  today is `src/lib/security/mock/seed-mock-data.ts`, which will pass
  `dev@localhost`. `decided_by` is a text snapshot, so this holds on Postgres
  where that account does not exist.
- **Scans stay out.** `reconcileFinding` and `resolveFinding` are untouched; no
  ingestion path calls `recordDecision`. The NEW path clearing
  `statusChangedBy` cannot orphan history: NEW means an unseen fingerprint,
  hence a new finding id, hence no rows to orphan.

### Section 3 — read path and UI (approved)

- `listDecisionHistory(id)` returns newest-first, both drivers, asserted in the
  contract suite.
- Route `GET /api/security/findings/[id]/history` —
  `protectedRoute<{ params: Promise<{ id: string }> }>`, returns `{ decisions }`,
  404 when the finding is absent, mirroring the sibling `[id]` route so
  existence leaks identically. **Any signed-in user may read it**, viewers
  included; `requireApprover()` stays on the write path only.
- `FindingDetails` gains an optional
  `loadHistory?: (id) => Promise<FindingDecision[]>` prop, injected the way
  `onApplyStatus` already is. Absent ⇒ no timeline, fail closed like
  `canDecide`. This keeps `fetch` out of the component and lets tests await the
  expected call instead of racing it.
- Three states: loading, empty, list. The empty state reads "Earlier decisions
  were not recorded." — the visible consequence of the no-backfill decision.
- Each row: `dev@localhost moved OPEN → ACCEPTED_RISK`, timestamp through
  `formatDateTime`, justification below as text. JSX escaping only; the
  no-`dangerouslySetInnerHTML` rule is absolute even though the reason is human
  input rather than scanner output.
- After a successful decision the drawer refetches rather than optimistically
  prepending.

### Section 4 — not yet presented

Errors, security and testing. Nothing agreed. Expect it to cover: what
`recordDecision` does when the finding vanishes mid-call, the contract-suite
assertions both drivers must pass, the route test, the component tests for the
three timeline states, and confirmation that no error message quotes a
credential.

## Task list state

Tasks 1–3 completed, 4 in progress (present the design), 5–7 pending (write and
commit the spec, self-review, user review). Terminal state of brainstorming is
invoking `superpowers:writing-plans` — no other skill.

## Decisions from the auth work — do not relitigate

- Local accounts, `scrypt` from `node:crypto`. Server-side revocable sessions.
- Both storage drivers, one contract suite.
- Everything behind the login except `POST /api/security/scans`, which keeps its
  bearer token for CI.
- Two roles, `VIEWER` / `APPROVER`. No third role, no permission table.
- `statusChangedBy` is a denormalized text email, never a foreign key.
- No backfill of `status_changed_by`; no attribution on scanner transitions.
- The UI is not the boundary — `setFindingStatusAction` re-checks the role
  regardless of what the drawer rendered. `canDecide` defaults to `false`.
- Enforcement is structural: `protectedRoute()` on routes, `requireUser()` in the
  layout *and* in each page.
- Provisioning is a CLI. No self-signup, admin UI, SSO/OIDC or password reset.
- Execution is **inline**, not subagent-driven: this harness does not spawn
  agents unasked.

## Traps

- **`src/proxy.ts` is not a security boundary.** Cookie presence only, never
  validity. Layouts do not re-run on client-side navigation.
- **`server-only` is aliased to its own `empty.js` in `vitest.config.mts`.**
  Without it no test can import the auth container or the guards.
- **The secret-scan hook blocks credential-shaped literals, including fake ones**
  — and blocks *this file* too if it quotes one. The auth contract suite's
  placeholder hash is assembled at runtime from two fragments.
- **scrypt `N` must stay 16384** (memory is roughly `N * r * 128`; 32768 with
  r=8 exceeds Node's 32 MB `maxmem`), and the parameters are duplicated in
  `scripts/user.mjs` on purpose. Change one, change both.
- **The CLI cannot work against the memory driver** — separate process. To test
  the viewer role there, change the seeded account's role in the seed.
- Port 5432 on this machine is an SSH tunnel. Test container is on **5433**.
- The container is cached on `globalThis`; seeding and wiring changes need a dev
  server restart. `resetAuthContainer()` is the test seam.
- `.claude/launch.json` has `"autoPort": true` — the dev server does not come up
  on 3000. `preview_list` then `preview_stop` if one is still running.
- The dev-server browser pane reported a **0x0 viewport**; drive forms through
  `javascript_tool` instead of coordinate clicks.
- Mock data is tuned to 23 open / 3 critical / 7 high / 13 medium / 0 low.
  Adding a `dev@localhost` signature to the seeded acceptance does not change
  the status distribution, so those numbers must stay put.
