# Finding Decision History Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline execution — this session's recorded decision) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Append-only audit trail of human status decisions: who moved a finding, from what, to what, when, and why — atomic with the status change, visible as a timeline in the finding drawer.

**Architecture:** New `FindingDecision` domain type + `finding_decisions` table. `SecurityFindingRepository` gains exactly two methods — `recordDecision` (patch + append in one transaction) and `listDecisionHistory` (newest first). `setFindingStatus` builds the decision from the transition it already computed and calls `recordDecision` instead of `update`. Read path: `GET /api/security/findings/[id]/history` (any signed-in user) + a timeline section in `FindingDetails` fed by an injected `loadHistory` prop.

**Tech Stack:** Next.js 16 App Router, TypeScript strict, `pg`, Vitest. No new dependencies.

**Context:** Spec approved and committed at `docs/superpowers/specs/2026-08-12-finding-decision-history-design.md` (`a6e0057`). The finding row keeps its current-decision snapshot (`statusReason`/`statusChangedAt`/`statusChangedBy`); history is additive. Human decisions only — scanner transitions record nothing. No backfill.

## Global Constraints

- **Deployment target is Azure, not Vercel** (user decision 2026-08-12): nothing Vercel-specific may be introduced. This plan adds none — plain Next.js + `pg` over `DATABASE_URL` (works against Azure Database for PostgreSQL).
- Invariant 4: `firstDetectedAt` never overwritten; merge path restores `statusReason`/`statusChangedAt`/`statusChangedBy`, NEW path clears them. `reconcileFinding` and `resolveFinding` are **untouched** by this plan.
- No `dangerouslySetInnerHTML` anywhere; JSX escaping only.
- Migrations are forward-only; new file `db/migrations/005_finding_decisions.sql`, never edit an applied one.
- Retry (`withRetry`) wraps whole operations from `BEGIN`, never a statement inside an open transaction.
- The service generates the decision id (`dec_${randomUUID()}`); Postgres insert is `ON CONFLICT (id) DO NOTHING` (retry-replay safety).
- Decision history ordering: `decidedAt DESC, id DESC` in both drivers.
- Empty-state copy, exact: `Earlier decisions were not recorded.`
- Mock headline numbers must stay 23 open / 3 critical / 7 high / 13 medium / 0 low.
- No credential-shaped literals in code or tests (secret-scan hook blocks the commit). Use `approver@example.com`-style addresses.
- Verification gate: `npm run lint && npm run typecheck && npm test && npm run build` with `TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test` (container `dashboard-test-pg`, port 5433 — 5432 is an SSH tunnel).

---

### Task 1: Domain type, migration, repository interface, memory driver, contract tests

**Files:**
- Create: `src/domain/security/decision.ts`
- Create: `db/migrations/005_finding_decisions.sql`
- Modify: `src/domain/security/index.ts` (add export)
- Modify: `src/lib/security/repository/security-finding-repository.ts` (two methods)
- Modify: `src/lib/security/repository/memory-security-finding-repository.ts`
- Test: `tests/repository/repository-contract.ts` (new describe block; memory suite runs it via `tests/repository/memory-repository.test.ts` unchanged)

**Interfaces:**
- Produces: `FindingDecision { id, findingId, fromStatus, toStatus, reason?, decidedBy, decidedAt }` (all strings; `fromStatus`/`toStatus` are `FindingStatus`); `recordDecision(id: string, patch: Partial<SecurityFinding>, decision: FindingDecision): Promise<SecurityFinding | null>`; `listDecisionHistory(id: string): Promise<FindingDecision[]>`.

- [ ] **Step 1: Write `src/domain/security/decision.ts`**

```ts
import type { FindingStatus } from "./enums";

/**
 * One human decision about a finding's status: who moved it, from what, to
 * what, and why. Append-only — nothing updates or deletes a recorded decision.
 *
 * Scanner-driven transitions (auto-resolve, reopen-by-scan) never appear here:
 * no person made them, and an attributed audit trail must not invent authors.
 */
export interface FindingDecision {
  id: string;
  findingId: string;
  fromStatus: FindingStatus;
  toStatus: FindingStatus;
  /** Nullable only because reopening to OPEN permits an absent justification. */
  reason?: string;
  /** Email snapshot of the decider. Text, not a foreign key — same reasoning as statusChangedBy. */
  decidedBy: string;
  /** ISO-8601 UTC instant. */
  decidedAt: string;
}
```

Add to `src/domain/security/index.ts` (alphabetical position, after `./enums` line style):

```ts
export * from "./decision";
```

- [ ] **Step 2: Write `db/migrations/005_finding_decisions.sql`**

```sql
-- Append-only history of human status decisions.
--
-- The finding row keeps the current-decision snapshot (status_reason,
-- status_changed_at, status_changed_by); this table is the trail behind it.
-- Rows are inserted by recordDecision and never updated or deleted.
--
-- Unlike status_changed_by, finding_id takes a foreign key: findings are never
-- deleted (the repository has no delete method), so the FK costs nothing.
-- CASCADE states the correct behavior for a path that is not exercised.
--
-- decided_by is NOT NULL: requireApprover() guarantees a session, so a row
-- without an author is a bug and the schema says so.

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

Note: `security_findings.id` must have a UNIQUE constraint for the FK — it does (verify with `grep -n "id" db/migrations/001_init.sql`; the merge path pins `id: existing.id` so it is stable).

- [ ] **Step 3: Add the two methods to `SecurityFindingRepository`** (`src/lib/security/repository/security-finding-repository.ts`)

```ts
import type { FindingDecision } from "@/domain/security/decision";
```

After `update(...)`:

```ts
  /**
   * Apply a status patch and append the decision that caused it, atomically:
   * both land or neither does. Returns null — writing nothing — when the
   * finding does not exist. Replay-safe: a decision id already stored is not
   * appended twice, because retry may replay a transaction whose COMMIT
   * acknowledgement was lost.
   */
  recordDecision(
    id: string,
    patch: Partial<SecurityFinding>,
    decision: FindingDecision,
  ): Promise<SecurityFinding | null>;

  /** Every recorded decision for a finding, newest first. */
  listDecisionHistory(id: string): Promise<FindingDecision[]>;
```

- [ ] **Step 4: Write the failing contract tests** — append a describe block inside `runSecurityFindingRepositoryContract` in `tests/repository/repository-contract.ts`. Add imports at top: `import type { FindingDecision } from "@/domain/security/decision";`

```ts
    // --- decision history ----------------------------------------------------

    describe("decision history", () => {
      function decision(
        overrides: Partial<FindingDecision> = {},
      ): FindingDecision {
        return {
          id: "dec_1",
          findingId: "fnd_a",
          fromStatus: "OPEN",
          toStatus: "ACCEPTED_RISK",
          reason: "Mitigated by a compensating control.",
          decidedBy: "approver@example.com",
          decidedAt: "2026-08-11T09:00:00.000Z",
          ...overrides,
        };
      }

      it("applies the patch and appends the decision in one call", async () => {
        const updated = await repository.recordDecision(
          "fnd_a",
          {
            status: "ACCEPTED_RISK",
            statusReason: "Mitigated by a compensating control.",
            statusChangedAt: "2026-08-11T09:00:00.000Z",
            statusChangedBy: "approver@example.com",
          },
          decision(),
        );

        expect(updated?.status).toBe("ACCEPTED_RISK");
        expect((await repository.findById("fnd_a"))?.status).toBe(
          "ACCEPTED_RISK",
        );

        const history = await repository.listDecisionHistory("fnd_a");
        expect(history).toHaveLength(1);
        expect(history[0]).toMatchObject({
          id: "dec_1",
          findingId: "fnd_a",
          fromStatus: "OPEN",
          toStatus: "ACCEPTED_RISK",
          reason: "Mitigated by a compensating control.",
          decidedBy: "approver@example.com",
          decidedAt: "2026-08-11T09:00:00.000Z",
        });
      });

      it("returns null for an unknown finding and records nothing", async () => {
        const result = await repository.recordDecision(
          "fnd_missing",
          { status: "ACCEPTED_RISK" },
          decision({ findingId: "fnd_missing" }),
        );

        // The atomicity assertion: no patched finding, therefore no row.
        expect(result).toBeNull();
        expect(await repository.listDecisionHistory("fnd_missing")).toEqual([]);
      });

      it("lists newest first with a deterministic tiebreak", async () => {
        await repository.recordDecision(
          "fnd_a",
          { status: "ACCEPTED_RISK" },
          decision({ id: "dec_a", decidedAt: "2026-08-10T09:00:00.000Z" }),
        );
        await repository.recordDecision(
          "fnd_a",
          { status: "OPEN" },
          decision({
            id: "dec_b",
            fromStatus: "ACCEPTED_RISK",
            toStatus: "OPEN",
            reason: undefined,
            decidedAt: "2026-08-11T09:00:00.000Z",
          }),
        );
        await repository.recordDecision(
          "fnd_a",
          { status: "SUPPRESSED" },
          decision({
            id: "dec_c",
            toStatus: "SUPPRESSED",
            decidedAt: "2026-08-11T09:00:00.000Z",
          }),
        );

        const history = await repository.listDecisionHistory("fnd_a");
        // Equal decidedAt on dec_b and dec_c: id DESC breaks the tie.
        expect(history.map((entry) => entry.id)).toEqual([
          "dec_c",
          "dec_b",
          "dec_a",
        ]);
      });

      it("stores a replayed decision id once", async () => {
        await repository.recordDecision(
          "fnd_a",
          { status: "ACCEPTED_RISK" },
          decision(),
        );
        await repository.recordDecision(
          "fnd_a",
          { status: "ACCEPTED_RISK" },
          decision(),
        );

        expect(await repository.listDecisionHistory("fnd_a")).toHaveLength(1);
      });

      it("returns an empty history for an undecided finding", async () => {
        expect(await repository.listDecisionHistory("fnd_b")).toEqual([]);
      });

      it("round-trips an absent reason as undefined, not empty string", async () => {
        await repository.recordDecision(
          "fnd_a",
          { status: "SUPPRESSED" },
          decision({ reason: undefined, toStatus: "SUPPRESSED" }),
        );

        const [entry] = await repository.listDecisionHistory("fnd_a");
        expect(entry.reason).toBeUndefined();
      });

      it("refuses to change identity through recordDecision", async () => {
        const updated = await repository.recordDecision(
          "fnd_a",
          { id: "fnd_hacked", fingerprint: "fp_hacked", status: "ACCEPTED_RISK" },
          decision(),
        );

        expect(updated?.id).toBe("fnd_a");
        expect(updated?.fingerprint).toBe("a");
      });
    });
```

- [ ] **Step 5: Run memory suite, verify failures**

Run: `npx vitest run tests/repository/memory-repository.test.ts`
Expected: FAIL — `recordDecision is not a function` (plus a TypeScript error on the class not implementing the interface; that is the point).

- [ ] **Step 6: Implement in the memory driver** (`memory-security-finding-repository.ts`). Import `FindingDecision` from `@/domain/security/decision`. Add field + methods after `update`:

```ts
  /** finding id -> decisions in append order. Sorted on read, like Postgres. */
  private readonly decisions = new Map<string, FindingDecision[]>();
```

```ts
  async recordDecision(
    id: string,
    patch: Partial<SecurityFinding>,
    decision: FindingDecision,
  ): Promise<SecurityFinding | null> {
    const existing = await this.findById(id);
    if (!existing) return null;

    // Identity is not patchable: allowing it would silently orphan history.
    const { id: _id, fingerprint: _fingerprint, ...safePatch } = patch;
    void _id;
    void _fingerprint;

    // One synchronous block: the finding update and the append cannot be
    // observed half-done, which is the transaction the Postgres driver runs.
    const updated: SecurityFinding = { ...existing, ...safePatch };
    this.findings.set(existing.fingerprint, updated);

    const history = this.decisions.get(id) ?? [];
    // Same idempotency Postgres gets from ON CONFLICT (id) DO NOTHING: a
    // replayed decision id is not appended twice.
    if (!history.some((entry) => entry.id === decision.id)) {
      history.push({ ...decision });
    }
    this.decisions.set(id, history);

    return updated;
  }

  async listDecisionHistory(id: string): Promise<FindingDecision[]> {
    const history = this.decisions.get(id) ?? [];
    return [...history].sort(
      (a, b) =>
        b.decidedAt.localeCompare(a.decidedAt) || b.id.localeCompare(a.id),
    );
  }
```

- [ ] **Step 7: Run memory suite, verify pass**

Run: `npx vitest run tests/repository/memory-repository.test.ts`
Expected: PASS (all, including the 7 new tests).

- [ ] **Step 8: Commit**

```bash
git add src/domain/security/decision.ts src/domain/security/index.ts db/migrations/005_finding_decisions.sql src/lib/security/repository/security-finding-repository.ts src/lib/security/repository/memory-security-finding-repository.ts tests/repository/repository-contract.ts
git commit -m "feat: append-only decision history in the repository contract and memory driver"
```

---

### Task 2: Postgres driver + TRUNCATE fixes

**Files:**
- Modify: `src/lib/security/repository/postgres-security-finding-repository.ts`
- Modify: `tests/repository/postgres-repository.test.ts:46` (TRUNCATE)
- Modify: `tests/repository/postgres-ingestion.test.ts:63` (TRUNCATE)
- Test: contract suite via `tests/repository/postgres-repository.test.ts` (already wired; `prepareSchema` applies every file in `db/migrations/`, so 005 lands automatically)

**Interfaces:**
- Consumes: `FindingDecision`, interface methods from Task 1; existing `withRetry`, `reportRetry`, `toFinding`, `toParams`, `COLUMNS`, `iso`, `undef` in the same file.

**Trap:** with the FK in place, `TRUNCATE security_findings` throws `cannot truncate a table referenced in a foreign key constraint`. Three call sites must change (the two test files below, and the repository's own `truncate()` helper).

- [ ] **Step 1: Run Postgres contract suite, verify the new tests fail** (container up, `TEST_DATABASE_URL` exported)

Run: `TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test npx vitest run tests/repository/postgres-repository.test.ts`
Expected: FAIL — `recordDecision is not a function`.

- [ ] **Step 2: Implement in the Postgres driver.** Imports: add `FindingDecision` to the `@/domain/security` type imports (from `@/domain/security/decision`). Add a row type + mapper near `FindingRow`:

```ts
interface DecisionRow {
  id: string;
  finding_id: string;
  from_status: string;
  to_status: string;
  reason: string | null;
  decided_by: string;
  decided_at: Date;
}

function toDecision(row: DecisionRow): FindingDecision {
  return {
    id: row.id,
    findingId: row.finding_id,
    fromStatus: row.from_status as FindingDecision["fromStatus"],
    toStatus: row.to_status as FindingDecision["toStatus"],
    reason: undef(row.reason),
    decidedBy: row.decided_by,
    decidedAt: row.decided_at.toISOString(),
  };
}
```

Methods after `update(...)`:

```ts
  async recordDecision(
    id: string,
    patch: Partial<SecurityFinding>,
    decision: FindingDecision,
  ): Promise<SecurityFinding | null> {
    // Retried as one unit, from BEGIN, like saveMany. The replay hazard is the
    // decision INSERT — an append is not naturally idempotent — so it dedupes
    // on the service-generated id.
    return withRetry(() => this.recordDecisionOnce(id, patch, decision), {
      operation: "findings.recordDecision",
      onRetry: reportRetry,
    });
  }

  private async recordDecisionOnce(
    id: string,
    patch: Partial<SecurityFinding>,
    decision: FindingDecision,
  ): Promise<SecurityFinding | null> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");

      const found = await client.query(
        `SELECT ${COLUMNS} FROM security_findings f WHERE f.id = $1`,
        [id],
      );
      const row = found.rows[0] as FindingRow | undefined;
      if (!row) {
        await client.query("ROLLBACK");
        return null;
      }

      // Identity is not patchable — changing it would orphan history.
      const { id: _id, fingerprint: _fingerprint, ...safePatch } = patch;
      void _id;
      void _fingerprint;
      const updated: SecurityFinding = { ...toFinding(row), ...safePatch };

      // Full-column overwrite, mirroring saveMany: the merged finding is
      // authoritative. Params follow the COLUMNS order; $2 is the id.
      const result = await client.query(
        `UPDATE security_findings SET
           fingerprint = $1, scanner = $3, category = $4, severity = $5,
           title = $6, description = $7, repository_id = $8,
           repository_name = $9, branch = $10, commit_sha = $11,
           application_id = $12, environment = $13, file = $14,
           start_line = $15, end_line = $16, package_name = $17,
           package_version = $18, fixed_version = $19, cve = $20, cwe = $21,
           rule_id = $22, resource = $23, azure_resource_id = $24,
           subscription_id = $25, resource_group = $26, status = $27,
           first_detected_at = $28, last_detected_at = $29, resolved_at = $30,
           status_reason = $31, status_changed_at = $32,
           status_changed_by = $33, remediation = $34, source_url = $35,
           metadata = $36
         WHERE id = $2`,
        toParams(updated),
      );
      if (result.rowCount === 0) {
        // Findings are never deleted, so this cannot happen today; stated so
        // the atomicity guarantee does not depend on that staying true.
        await client.query("ROLLBACK");
        return null;
      }

      // ON CONFLICT DO NOTHING: a retry that replays a transaction whose
      // COMMIT acknowledgement was lost must not append a second row.
      await client.query(
        `INSERT INTO finding_decisions
           (id, finding_id, from_status, to_status, reason, decided_by, decided_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (id) DO NOTHING`,
        [
          decision.id,
          decision.findingId,
          decision.fromStatus,
          decision.toStatus,
          decision.reason ?? null,
          decision.decidedBy,
          decision.decidedAt,
        ],
      );

      await client.query("COMMIT");
      return updated;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async listDecisionHistory(id: string): Promise<FindingDecision[]> {
    const rows = await this.query<DecisionRow>(
      `SELECT id, finding_id, from_status, to_status, reason, decided_by, decided_at
       FROM finding_decisions
       WHERE finding_id = $1
       ORDER BY decided_at DESC, id DESC`,
      [id],
    );
    return rows.map(toDecision);
  }
```

Change the `truncate()` helper at the bottom of the class:

```ts
  /** Test helper: remove every row. Never called by application code. */
  async truncate(): Promise<void> {
    await this.query("TRUNCATE security_findings CASCADE");
  }
```

- [ ] **Step 3: Fix the two test-file TRUNCATEs.** In `tests/repository/postgres-repository.test.ts:46` and `tests/repository/postgres-ingestion.test.ts:63`, change `"TRUNCATE security_findings"` to `"TRUNCATE security_findings CASCADE"` (the finding_decisions FK now blocks the plain form).

- [ ] **Step 4: Run both Postgres suites, verify pass**

Run: `TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test npx vitest run tests/repository/postgres-repository.test.ts tests/repository/postgres-ingestion.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/security/repository/postgres-security-finding-repository.ts tests/repository/postgres-repository.test.ts tests/repository/postgres-ingestion.test.ts
git commit -m "feat: postgres decision history — one transaction, replay-safe append"
```

---

### Task 3: Service — build the decision, require `changedBy`

**Files:**
- Modify: `src/lib/security/services/security-service.ts` (`setFindingStatus` at :310, new `getDecisionHistory`)
- Modify: `src/lib/security/mock/seed-mock-data.ts:173` (pass `changedBy`)
- Test: `tests/services/finding-status.test.ts` (update all calls; replace one test; add history tests)
- Test: `tests/services/scan-ingestion.test.ts` (scanner transitions write nothing)

**Interfaces:**
- Consumes: `recordDecision` / `listDecisionHistory` from Tasks 1–2.
- Produces: `setFindingStatus(id, status, reason, options: { changedBy: string; now?: Date })` — **options and `changedBy` now required**; `getDecisionHistory(id: string): Promise<FindingDecision[] | null>` (null = finding absent, for the route's 404).
- Callers already passing `changedBy`: `src/app/dashboard/security/actions.ts:55` ✓ (no change). `tests/actions/finding-status-action.test.ts` stubs the service with an untyped `vi.fn()` ✓ (no change).

- [ ] **Step 1: Write the failing service tests.** In `tests/services/finding-status.test.ts`:

First, every existing `service.setFindingStatus(...)` call gains `changedBy` in its options (e.g. `{ now: NOW }` → `{ changedBy: "approver@example.com", now: NOW }`; calls that already pass `changedBy` keep theirs). **Delete** the test `"records no author when none is supplied"` — an author is now required by the type — and add in its place, inside the existing describe:

```ts
  it("generates a distinct dec_-prefixed id per decision", async () => {
    await service.setFindingStatus("fnd_1", "ACCEPTED_RISK", "Mitigated.", {
      changedBy: "approver@example.com",
      now: NOW,
    });
    await service.setFindingStatus("fnd_1", "OPEN", undefined, {
      changedBy: "approver@example.com",
      now: new Date("2026-08-13T10:00:00.000Z"),
    });

    const history = await findings.listDecisionHistory("fnd_1");
    expect(history).toHaveLength(2);
    expect(new Set(history.map((entry) => entry.id)).size).toBe(2);
    for (const entry of history) {
      expect(entry.id).toMatch(/^dec_/);
    }
  });
```

Then a new describe block in the same file:

```ts
describe("SecurityService.setFindingStatus decision history", () => {
  it("records the transition it applied", async () => {
    await service.setFindingStatus(
      "fnd_1",
      "ACCEPTED_RISK",
      "  Mitigated by the WAF rule shipped in PR 412.  ",
      { changedBy: "approver@example.com", now: NOW },
    );

    const [entry] = await findings.listDecisionHistory("fnd_1");
    expect(entry).toMatchObject({
      findingId: "fnd_1",
      fromStatus: "OPEN",
      toStatus: "ACCEPTED_RISK",
      // The stored reason is the validated, trimmed value — one path, not two.
      reason: "Mitigated by the WAF rule shipped in PR 412.",
      decidedBy: "approver@example.com",
      decidedAt: "2026-08-12T10:00:00.000Z",
    });
  });

  it("writes no history for a no-op transition", async () => {
    await service.setFindingStatus("fnd_1", "ACCEPTED_RISK", "Original.", {
      changedBy: "approver@example.com",
      now: NOW,
    });
    await service.setFindingStatus("fnd_1", "ACCEPTED_RISK", "Rewrite.", {
      changedBy: "second@example.com",
      now: NOW,
    });

    expect(await findings.listDecisionHistory("fnd_1")).toHaveLength(1);
  });

  it("writes no history for a rejected transition or reason", async () => {
    // Missing justification: rejected before the decision object exists.
    await expect(
      service.setFindingStatus("fnd_1", "ACCEPTED_RISK", undefined, {
        changedBy: "approver@example.com",
        now: NOW,
      }),
    ).rejects.toBeInstanceOf(InvalidStatusReasonError);

    // Disallowed transition: same guarantee.
    await service.setFindingStatus("fnd_1", "FALSE_POSITIVE", "Fixture.", {
      changedBy: "approver@example.com",
      now: NOW,
    });
    await expect(
      service.setFindingStatus("fnd_1", "SUPPRESSED", "Because.", {
        changedBy: "approver@example.com",
        now: NOW,
      }),
    ).rejects.toBeInstanceOf(InvalidStatusTransitionError);

    // Only the one successful decision is on the tape.
    expect(await findings.listDecisionHistory("fnd_1")).toHaveLength(1);
  });

  it("returns history newest first and null for an unknown finding", async () => {
    await service.setFindingStatus("fnd_1", "ACCEPTED_RISK", "Mitigated.", {
      changedBy: "approver@example.com",
      now: NOW,
    });
    await service.setFindingStatus("fnd_1", "OPEN", undefined, {
      changedBy: "second@example.com",
      now: new Date("2026-08-13T10:00:00.000Z"),
    });

    const history = await service.getDecisionHistory("fnd_1");
    expect(history?.map((entry) => entry.toStatus)).toEqual([
      "OPEN",
      "ACCEPTED_RISK",
    ]);

    expect(await service.getDecisionHistory("fnd_missing")).toBeNull();
  });
});
```

- [ ] **Step 2: Run, verify failures**

Run: `npx vitest run tests/services/finding-status.test.ts`
Expected: FAIL — TypeScript on the options type and `getDecisionHistory` missing.

- [ ] **Step 3: Implement in `security-service.ts`.** Add imports:

```ts
import { randomUUID } from "node:crypto";
import type { FindingDecision } from "@/domain/security/decision";
```

Change the signature (`options` loses its default and `changedBy` its `?`):

```ts
  async setFindingStatus(
    id: string,
    status: FindingStatus,
    reason: string | undefined,
    options: { changedBy: string; now?: Date },
  ): Promise<SecurityFinding | null> {
```

Update the doc comment's `changedBy` sentence to: `options.changedBy` is the deciding user's email, snapshotted onto the finding and onto the appended decision. The caller supplies it from the session; the service never guesses, and the type no longer lets a caller omit it.

Replace the final `return this.findings.update(...)` with:

```ts
    const decision: FindingDecision = {
      // The service, not the driver, generates the id: recordDecision retries
      // as a whole unit, and a replay after a lost COMMIT acknowledgement must
      // dedupe on a stable id rather than append a second row.
      id: `dec_${randomUUID()}`,
      findingId: id,
      fromStatus: finding.status,
      toStatus: status,
      reason: statusReason,
      decidedBy: options.changedBy,
      decidedAt: now.toISOString(),
    };

    return this.findings.recordDecision(
      id,
      {
        status,
        resolvedAt: status === "RESOLVED" ? now.toISOString() : undefined,
        // Reopening without a reason clears the old one: a justification written
        // for a status the finding no longer holds reads as a current decision.
        statusReason,
        statusChangedAt: now.toISOString(),
        // Attribution belongs to the change, not to the justification: this is
        // who made the change `statusChangedAt` timestamps.
        statusChangedBy: options.changedBy,
      },
      decision,
    );
```

Add after `setFindingStatus`:

```ts
  /**
   * Every human decision recorded for a finding, newest first. Null when the
   * finding does not exist, so the history route can 404 exactly as the
   * sibling finding route does.
   */
  async getDecisionHistory(id: string): Promise<FindingDecision[] | null> {
    const finding = await this.findings.findById(id);
    if (!finding) return null;
    return this.findings.listDecisionHistory(id);
  }
```

- [ ] **Step 4: Update the mock seed.** In `src/lib/security/mock/seed-mock-data.ts:173`, the `setFindingStatus` call gains a fourth argument:

```ts
    await security.setFindingStatus(
      target.id,
      "ACCEPTED_RISK",
      "Key vault purge protection is enforced by Azure Policy at the subscription level; the module flag is redundant here.",
      // The dev approver the memory container seeds. decided_by is a text
      // snapshot, so this also holds on Postgres where no such account exists.
      { changedBy: "dev@localhost" },
    );
```

- [ ] **Step 5: Add the scanner-transitions-write-nothing test.** In `tests/services/scan-ingestion.test.ts`, after the `"reopens a finding that comes back"` test:

```ts
  it("records no decision history for scanner-driven transitions", async () => {
    const { ingestion, findings } = build();

    // First scan opens findings; second (empty) resolves them; third reopens.
    await ingestion.ingest({
      ...baseRequest,
      scannedAt: "2026-08-01T10:00:00.000Z",
    });
    await ingestion.ingest({
      ...baseRequest,
      results: JSON.stringify({ results: [], errors: [], paths: {} }),
      scannedAt: "2026-08-06T10:00:00.000Z",
    });
    await ingestion.ingest({
      ...baseRequest,
      scannedAt: "2026-08-07T10:00:00.000Z",
    });

    // Auto-resolve and reopen-by-scan are evidence, not decisions: no person
    // made them, so the attributed trail stays empty.
    const page = await findings.findAll({ status: ["OPEN"] });
    expect(page.total).toBeGreaterThan(0);
    for (const found of page.items) {
      expect(await findings.listDecisionHistory(found.id)).toEqual([]);
    }
  });
```

(Match the empty-scan payload shape used by the existing `"auto-resolves findings the scan no longer reports"` test at `tests/services/scan-ingestion.test.ts:90` — reuse its exact empty-`results` fixture/literal if it differs from the above.)

- [ ] **Step 6: Run the service suites, verify pass**

Run: `npx vitest run tests/services/finding-status.test.ts tests/services/scan-ingestion.test.ts tests/actions/finding-status-action.test.ts`
Expected: PASS.

- [ ] **Step 7: Typecheck (catches any missed caller of the changed signature)**

Run: `npm run typecheck`
Expected: 0 errors.

- [ ] **Step 8: Commit**

```bash
git add src/lib/security/services/security-service.ts src/lib/security/mock/seed-mock-data.ts tests/services/finding-status.test.ts tests/services/scan-ingestion.test.ts
git commit -m "feat: setFindingStatus records the decision and requires its author"
```

---

### Task 4: History route

**Files:**
- Create: `src/app/api/security/findings/[id]/history/route.ts`
- Test: `tests/api/protected-routes.test.ts` (new describe)

**Interfaces:**
- Consumes: `service.getDecisionHistory` (Task 3), `protectedRoute` from `@/lib/auth/guards`, `errorResponse`/`errorToResponse`/`jsonResponse` from `@/lib/api/http`, `withSession(email, role)` from `tests/helpers/session.ts`.
- Produces: `GET /api/security/findings/:id/history` → 200 `{ decisions: FindingDecision[] }`, 401 anonymous, 404 unknown id.
- Fact: the memory container seeds mock data on first `getSecurityService()` in tests (`SECURITY_DATA_SOURCE` unset → mock, empty memory store), and `/api/security/findings` returns a `Page` — `body.items[0].id` is a real id.

- [ ] **Step 1: Write the failing route tests.** In `tests/api/protected-routes.test.ts`, add the import:

```ts
import { GET as historyGet } from "@/app/api/security/findings/[id]/history/route";
```

Append inside the top-level describe:

```ts
  describe("finding history", () => {
    const historyUrl = (id: string) =>
      `http://localhost/api/security/findings/${id}/history`;
    const routeContext = (id: string) => ({
      params: Promise.resolve({ id }),
    });

    it("refuses an anonymous request with 401", async () => {
      const response = await historyGet(
        new Request(historyUrl("fnd_any")),
        routeContext("fnd_any"),
      );

      expect(response.status).toBe(401);
    });

    it("serves a viewer: reading history needs no approver role", async () => {
      const { cookie } = await withSession(
        "history-viewer@example.com",
        "VIEWER",
      );

      const list = await findingsGet(
        new Request("http://localhost/api/security/findings", {
          headers: { cookie },
        }),
      );
      const page = await list.json();
      const id: string = page.items[0].id;

      const response = await historyGet(
        new Request(historyUrl(id), { headers: { cookie } }),
        routeContext(id),
      );

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toMatchObject({
        decisions: expect.any(Array),
      });
    });

    it("404s an unknown finding, exactly like the sibling route", async () => {
      const { cookie } = await withSession("history-404@example.com", "VIEWER");

      const response = await historyGet(
        new Request(historyUrl("fnd_missing"), { headers: { cookie } }),
        routeContext("fnd_missing"),
      );

      expect(response.status).toBe(404);
      await expect(response.json()).resolves.toMatchObject({
        error: { code: "NOT_FOUND" },
      });
    });
  });
```

- [ ] **Step 2: Run, verify failure**

Run: `npx vitest run tests/api/protected-routes.test.ts`
Expected: FAIL — cannot resolve the route module.

- [ ] **Step 3: Write the route** — `src/app/api/security/findings/[id]/history/route.ts`:

```ts
import { errorResponse, errorToResponse, jsonResponse } from "@/lib/api/http";
import { protectedRoute } from "@/lib/auth/guards";
import { getSecurityService } from "@/lib/security/container";

/**
 * GET /api/security/findings/:id/history
 *
 * The append-only decision trail for one finding, newest first. Requires a
 * session and nothing more: a viewer who may read a finding's current
 * justification may read its previous ones — requireApprover() guards writing
 * decisions, not reading them.
 *
 * 404 mirrors the sibling finding route, so the two endpoints leak existence
 * identically.
 */
export const GET = protectedRoute<{ params: Promise<{ id: string }> }>(
  async (_request, { routeContext }): Promise<Response> => {
    try {
      const { id } = await routeContext.params;

      const service = await getSecurityService();
      const decisions = await service.getDecisionHistory(id);

      if (decisions === null) {
        return errorResponse("NOT_FOUND", "Finding not found.", 404);
      }

      return jsonResponse({ decisions });
    } catch (error) {
      return errorToResponse(error);
    }
  },
);
```

- [ ] **Step 4: Run, verify pass**

Run: `npx vitest run tests/api/protected-routes.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/app/api/security/findings/\[id\]/history/route.ts tests/api/protected-routes.test.ts
git commit -m "feat: viewer-readable decision history route"
```

---

### Task 5: Drawer timeline

**Files:**
- Modify: `src/components/security/finding-details.tsx` (new prop + section)
- Modify: `src/components/security/findings-table.tsx` (fetch helper, thread the prop at :483)
- Test: `tests/components/finding-details.test.tsx` (new describe)

**Interfaces:**
- Consumes: `FindingDecision` type; route from Task 4; `formatDateTime` from `@/lib/format` (already imported in finding-details).
- Produces: `FindingDetails` prop `loadHistory?: (id: string) => Promise<FindingDecision[]>` — absent ⇒ no timeline section at all (fail closed, like `canDecide`).

- [ ] **Step 1: Write the failing component tests.** In `tests/components/finding-details.test.tsx`, add `import type { FindingDecision } from "@/domain/security/decision";` and a helper + describe at the end:

```tsx
function historyEntry(
  overrides: Partial<FindingDecision> = {},
): FindingDecision {
  return {
    id: "dec_1",
    findingId: "fnd_1",
    fromStatus: "OPEN",
    toStatus: "ACCEPTED_RISK",
    reason: "Mitigated by the WAF rule shipped in PR 412.",
    decidedBy: "approver@example.com",
    decidedAt: "2026-08-12T10:00:00.000Z",
    ...overrides,
  };
}

describe("FindingDetails decision history", () => {
  it("renders no timeline when no loader is supplied", () => {
    render(<FindingDetails finding={finding()} onClose={() => {}} />);

    expect(screen.queryByText("Decision history")).toBeNull();
  });

  it("shows a loading state, then the timeline", async () => {
    const loadHistory = vi
      .fn()
      .mockResolvedValue([
        historyEntry({ id: "dec_2" }),
        historyEntry({
          id: "dec_1",
          fromStatus: "ACCEPTED_RISK",
          toStatus: "OPEN",
          reason: undefined,
          decidedBy: "second@example.com",
          decidedAt: "2026-08-11T10:00:00.000Z",
        }),
      ]);

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        loadHistory={loadHistory}
      />,
    );

    expect(screen.getByText(/loading decision history/i)).toBeTruthy();

    // Await the expected call, never the last render: the debounce-race rule.
    await waitFor(() => expect(loadHistory).toHaveBeenCalledWith("fnd_1"));
    expect(
      await screen.findByText("Mitigated by the WAF rule shipped in PR 412."),
    ).toBeTruthy();
    expect(screen.getByText("approver@example.com")).toBeTruthy();
    expect(screen.getByText("second@example.com")).toBeTruthy();
  });

  it("explains an empty history rather than implying none happened", async () => {
    const loadHistory = vi.fn().mockResolvedValue([]);

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        loadHistory={loadHistory}
      />,
    );

    expect(
      await screen.findByText("Earlier decisions were not recorded."),
    ).toBeTruthy();
  });

  it("reports a failed load without disabling the decision form", async () => {
    const loadHistory = vi.fn().mockRejectedValue(new Error("boom"));

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={vi.fn()}
        canDecide
        loadHistory={loadHistory}
      />,
    );

    expect(
      await screen.findByText("Decision history could not be loaded."),
    ).toBeTruthy();
    // The audit view is not a gate: the form is still usable.
    expect(screen.getByLabelText(/change status to/i)).toBeTruthy();
  });

  it("refetches when the finding's decision snapshot changes", async () => {
    const loadHistory = vi.fn().mockResolvedValue([]);

    const { rerender } = render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        loadHistory={loadHistory}
      />,
    );
    await waitFor(() => expect(loadHistory).toHaveBeenCalledTimes(1));

    // What handleStatusChanged does after a successful decision: the drawer
    // receives the stored finding, whose statusChangedAt moved.
    rerender(
      <FindingDetails
        finding={finding({
          status: "ACCEPTED_RISK",
          statusChangedAt: "2026-08-12T11:00:00.000Z",
        })}
        onClose={() => {}}
        loadHistory={loadHistory}
      />,
    );

    await waitFor(() => expect(loadHistory).toHaveBeenCalledTimes(2));
  });
});
```

- [ ] **Step 2: Run, verify failures**

Run: `npx vitest run tests/components/finding-details.test.tsx`
Expected: existing tests PASS, the five new ones FAIL (no `loadHistory` prop, no section).

- [ ] **Step 3: Implement in `finding-details.tsx`.** Add imports:

```tsx
import type { FindingDecision } from "@/domain/security/decision";
```

Add the prop (after `canDecide` in both the destructuring and the type):

```tsx
  /**
   * Loads the decision trail for this finding. Injected like `onApplyStatus`
   * so the component stays fetch-free and tests await the injected call.
   * Absent ⇒ no timeline at all, failing closed like `canDecide`.
   */
  loadHistory?: (id: string) => Promise<FindingDecision[]>;
```

State + effect inside `FindingDetails` (after `safeSourceUrl`):

```tsx
  const [history, setHistory] = useState<
    | { kind: "loading" }
    | { kind: "error" }
    | { kind: "loaded"; decisions: FindingDecision[] }
  >({ kind: "loading" });

  useEffect(() => {
    if (!loadHistory) return;
    let cancelled = false;
    setHistory({ kind: "loading" });
    loadHistory(finding.id).then(
      (decisions) => {
        if (!cancelled) setHistory({ kind: "loaded", decisions });
      },
      () => {
        // The audit view is not a gate: the drawer and the decision form stay
        // usable when history cannot load.
        if (!cancelled) setHistory({ kind: "error" });
      },
    );
    return () => {
      cancelled = true;
    };
    // statusChangedAt re-runs the fetch after a successful decision, so the
    // timeline shows what was stored rather than an optimistic guess.
  }, [loadHistory, finding.id, finding.statusChangedAt]);
```

(`useState` is already imported.) Render after the `Decision` section, before `Remediation`:

```tsx
          {loadHistory && (
            <Section title="Decision history">
              {history.kind === "loading" ? (
                <p className="text-ink-faint text-sm">
                  Loading decision history…
                </p>
              ) : history.kind === "error" ? (
                <p className="text-ink-faint text-sm">
                  Decision history could not be loaded.
                </p>
              ) : history.decisions.length === 0 ? (
                /* The no-backfill decision, visible: findings decided before
                   history shipped have a status but no recorded trail. */
                <p className="text-ink-faint text-sm">
                  Earlier decisions were not recorded.
                </p>
              ) : (
                <ol className="divide-line divide-y">
                  {history.decisions.map((decision) => (
                    <li key={decision.id} className="py-2">
                      <p className="text-ink text-xs">
                        <span className="font-mono">{decision.decidedBy}</span>{" "}
                        moved{" "}
                        <span className="font-mono">{decision.fromStatus}</span>{" "}
                        →{" "}
                        <span className="font-mono">{decision.toStatus}</span>
                      </p>
                      <p className="text-ink-faint mt-0.5 font-mono text-[10px]">
                        {formatDateTime(decision.decidedAt)}
                      </p>
                      {decision.reason && (
                        <p className="text-ink-muted mt-1 text-sm leading-relaxed break-words whitespace-pre-wrap">
                          {decision.reason}
                        </p>
                      )}
                    </li>
                  ))}
                </ol>
              )}
            </Section>
          )}
```

All strings render through JSX escaping — reasons and emails are human input, and the no-`dangerouslySetInnerHTML` rule is absolute anyway.

- [ ] **Step 4: Thread the loader in `findings-table.tsx`.** Add imports:

```tsx
import type { FindingDecision } from "@/domain/security/decision";
```

Module-level helper (near `buildFindingsQuery`):

```tsx
/**
 * History loads through the API rather than inside FindingDetails, so the
 * drawer stays fetch-free and component tests await an injected loader
 * instead of stubbing global fetch.
 */
async function fetchDecisionHistory(id: string): Promise<FindingDecision[]> {
  const response = await fetch(
    `/api/security/findings/${encodeURIComponent(id)}/history`,
  );
  if (!response.ok) {
    throw new Error(`History request failed with status ${response.status}`);
  }
  const body = (await response.json()) as { decisions: FindingDecision[] };
  return body.decisions;
}
```

At the `FindingDetails` usage (`findings-table.tsx:483`), add the prop:

```tsx
          loadHistory={fetchDecisionHistory}
```

- [ ] **Step 5: Run component suites, verify pass**

Run: `npx vitest run tests/components/finding-details.test.tsx tests/components/findings-table.test.tsx`
Expected: PASS. (findings-table tests stub `fetch`; the drawer only mounts on row click — if a findings-table test opens the drawer and its fetch stub rejects the history URL, extend that stub to answer `{ decisions: [] }` for URLs matching `/history`.)

- [ ] **Step 6: Commit**

```bash
git add src/components/security/finding-details.tsx src/components/security/findings-table.tsx tests/components/finding-details.test.tsx
git commit -m "feat: decision-history timeline in the finding drawer"
```

---

### Task 6: README, full gate, live pass

**Files:**
- Modify: `README.md` (decision-history subsection under the finding lifecycle section)

- [ ] **Step 1: README.** Under the finding lifecycle / manual status section, add a short subsection:

```markdown
### Decision history

Every human status change is also appended to `finding_decisions`: who moved
the finding, from which status to which, when, and the justification. The
write is atomic with the status change — one transaction, both or neither.
The drawer shows the trail newest-first.

What is *not* recorded, on purpose:

- Scanner-driven transitions (auto-resolve, reopen-by-scan). No person made
  them; `firstDetectedAt`, `resolvedAt` and the trend data describe the
  machine's side.
- Decisions taken before this feature shipped. They were not backfilled — the
  drawer says "Earlier decisions were not recorded." rather than showing a
  synthesized row.

History is append-only at the interface level: neither storage driver exposes
an update or delete for decisions. Reading the trail requires a session but no
role; writing decisions still requires `APPROVER`.
```

(Adjust heading level/placement to match the README's existing structure; if a "Known limitations" entry about missing audit history exists, remove it.)

- [ ] **Step 2: Full gate**

```bash
npm run lint && npm run typecheck && TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test npm test && npm run build
```

Expected: lint 0, typecheck 0, all tests pass (486 + new ones, none skipped except any unrelated), build green. Start the `dashboard-test-pg` container first if it is down. Postgres needs `005` applied — `prepareSchema` in tests does it automatically; for a dev database run `npm run db:migrate`.

- [ ] **Step 3: Live pass** (dev server via `preview_start`; container cached on `globalThis`, so restart the server, do not just save; `.claude/launch.json` has `autoPort: true` — not port 3000; the browser pane has a 0x0-viewport history, drive via `javascript_tool` if clicks fail):

1. Sign in as the seeded dev approver. Open the seeded ACCEPTED_RISK finding (Checkov, `CKV_AZURE_112`) — timeline shows one row: `dev@localhost moved OPEN → ACCEPTED_RISK` with the seeded justification.
2. Reopen it, then accept it again with a new reason — timeline shows three rows newest-first, stat tiles still show 23 open / 3 critical / 7 high / 13 medium / 0 low after the final state matches the seed.
3. Open a finding never decided — "Earlier decisions were not recorded."
4. Change the seeded account's role to VIEWER in the seed (memory driver ignores the CLI), restart, confirm: timeline visible, decision control locked.
5. Revert any seed edit from step 4.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document decision history"
```

---

## Self-Review (done)

- **Spec coverage:** data model → T1; atomic write path + replay idempotency → T1/T2; service + required author + seed → T3; route → T4; timeline (3 states + fail-open error + refetch) → T5; docs + verification → T6. Scanner-paths-record-nothing → T3 step 5. Ordering tiebreak → T1 step 4 / T2. No-backfill copy → T5. ✓
- **Type consistency:** `recordDecision(id, patch, decision)` / `listDecisionHistory(id)` / `getDecisionHistory(id)` / `loadHistory(id)` names and shapes match across tasks; `FindingDecision` fields identical everywhere. ✓
- **Placeholders:** none; the one deliberate adaptation point (empty-scan fixture shape in T3 step 5, fetch-stub in T5 step 5) is called out with the exact fallback. ✓
