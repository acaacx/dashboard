# Dashboard Authentication — Plan 2: Roles and Attribution

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record who signed a finding's decision, and stop a viewer from signing one.

**Architecture:** `SecurityFinding` gains `statusChangedBy` — the deciding user's email, snapshotted as text rather than joined through a foreign key, because a risk acceptance is an audit record that must survive the person leaving. It is threaded through `reconcileFinding` exactly as `statusReason` already is: the merge path restores it from the stored finding, the NEW path clears it, so a scan can neither erase attribution nor plant it. Enforcement is a new `requireApprover()` guard that throws an `AuthDomainError`, which `setFindingStatusAction` maps to `{ ok: false, code, message }`; the drawer receives a `canDecide` boolean and shows a viewer a disabled control with the reason.

**Tech Stack:** Next.js 16 (App Router), React 19, TypeScript strict, `pg`, `zod`, Vitest. **No new dependency is added by this plan.**

Spec: `docs/superpowers/specs/2026-08-08-dashboard-authentication-design.md`
Plan 1 (complete): `docs/superpowers/plans/2026-08-08-dashboard-authentication-wall.md`

## Global Constraints

- **No new runtime dependency.** Nothing here needs one.
- **`statusChangedBy` is text, never a foreign key.** No `REFERENCES users`, no `ON DELETE` clause. The spec rejected both answers: `RESTRICT` means a departed employee can never be deleted, `SET NULL` silently erases attribution from real risk acceptances.
- **A scanner has no standing to record a human decision.** `reconcileFinding`'s NEW path must clear `statusChangedBy`, and no adapter may set it.
- **Migrations are forward-only.** Add `db/migrations/004_status_changed_by.sql`. Never edit `001_init.sql`, `002_finding_status_reason.sql` or `003_auth.sql`.
- **The UI is not a security boundary.** `canDecide` decides what renders; `setFindingStatusAction` re-checks the role regardless, the same way it already re-checks the manual-`RESOLVED` ban.
- **Fail closed.** `canDecide` defaults to `false` — a component cannot know who is looking, so a caller that does not say gets the locked control.
- **Never log or return a password or session token.** No error added here quotes a credential.
- **Both storage drivers stay in step.** Anything the PostgreSQL finding repository persists, the contract suite asserts for both drivers.
- Port 5432 on the development machine is an SSH tunnel. The test container is on **5433**.
- Verification gate for every task: `npm run lint && npm run typecheck && npm test`. Run with `TEST_DATABASE_URL` set so the PostgreSQL suites run rather than skip:

```bash
export TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test
```

The full gate — including `npm run build` — runs once at the end, in Task 7.

## File Structure

**Created**

| File | Responsibility |
|---|---|
| `db/migrations/004_status_changed_by.sql` | adds `status_changed_by TEXT` to `security_findings` |
| `tests/auth/require-approver.test.ts` | the role guard against the real in-memory store |

**Modified**

| File | Change |
|---|---|
| `src/domain/security/finding.ts` | `statusChangedBy?: string` |
| `src/domain/auth/user.ts` | `isApprover()` |
| `src/domain/auth/errors.ts` | `NotAuthenticatedError`, `ForbiddenError` |
| `src/lib/security/lifecycle.ts` | thread `statusChangedBy` through both `reconcileFinding` paths |
| `src/lib/security/repository/postgres-security-finding-repository.ts` | column, row type, mapping, params, upsert |
| `src/lib/security/services/security-service.ts` | `setFindingStatus` records the deciding email |
| `src/lib/auth/guards.ts` | `requireApprover()` |
| `src/app/dashboard/security/actions.ts` | enforce approver, thread the email, refresh the stale comment |
| `src/app/dashboard/security/page.tsx` | pass `canDecide` from the session user |
| `src/components/security/findings-table.tsx` | pass `canDecide` through |
| `src/components/security/finding-details.tsx` | attribution line, locked decision control, sign-in link |
| `README.md` | authentication section gains roles and attribution; one limitation removed |
| `tests/lifecycle.test.ts` | both attribution directions |
| `tests/repository/repository-contract.ts` | persistence across both drivers |
| `tests/services/finding-status.test.ts` | records the author; options-object call sites |
| `tests/actions/finding-status-action.test.ts` | viewer forbidden, no session unauthenticated, email threaded |
| `tests/auth/user-cli.test.ts` | attribution survives offboarding |
| `tests/components/finding-details.test.tsx` | viewer locked, approver working, author rendered |
| `tests/components/findings-table.test.tsx` | `canDecide` passed through |

---

### Task 1: `statusChangedBy` on the domain type and through the lifecycle

The field and the two lines of `reconcileFinding` that make it survive a scan without being forgeable by one. Nothing stores it yet — that is Task 2.

**Files:**
- Modify: `src/domain/security/finding.ts` (after `statusChangedAt`, ~line 89)
- Modify: `src/lib/security/lifecycle.ts:63` (NEW path) and `src/lib/security/lifecycle.ts:94` (merge path)
- Test: `tests/lifecycle.test.ts` (in the existing `describe("reconcileFinding and human decisions")`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `SecurityFinding.statusChangedBy?: string`. Every later task reads or writes this exact name.

- [x] **Step 1: Write the failing tests**

Append these two tests inside the existing `describe("reconcileFinding and human decisions", …)` block in `tests/lifecycle.test.ts`, after the "does not invent a justification" test:

```ts
  it("preserves the deciding email when a scan sees the finding again", () => {
    const existing = finding({
      status: "ACCEPTED_RISK",
      statusReason: "Compensating control in the WAF, reviewed 2026-08-01.",
      statusChangedAt: "2026-08-01T09:00:00.000Z",
      statusChangedBy: "approver@example.com",
    });

    const { finding: merged } = reconcileFinding(
      existing,
      finding({ lastDetectedAt: "2026-08-12T00:00:00.000Z" }),
    );

    // Dropping this line lets the next scan erase attribution from a real risk
    // acceptance.
    expect(merged.statusChangedBy).toBe("approver@example.com");
  });

  it("refuses attribution supplied by a scanner adapter", () => {
    const { finding: merged } = reconcileFinding(
      undefined,
      finding({ statusChangedBy: "attacker@example.com" }),
    );

    // Dropping this line lets a crafted scanner payload sign a decision.
    expect(merged.statusChangedBy).toBeUndefined();
  });
```

- [x] **Step 2: Run the tests to verify they fail**

```bash
npx vitest run tests/lifecycle.test.ts
```

Expected: FAIL — TypeScript rejects `statusChangedBy` as an unknown property of `Partial<SecurityFinding>`.

- [x] **Step 3: Add the field**

In `src/domain/security/finding.ts`, immediately after the `statusChangedAt` declaration:

```ts
  /** ISO-8601 UTC instant of the last manual status change. */
  statusChangedAt?: string;

  /**
   * Email of the person who made the last manual status change, snapshotted at
   * the moment of the decision.
   *
   * Denormalized on purpose. A risk acceptance is an audit record and has to
   * survive the person leaving: a foreign key would force a choice between
   * never deleting a departed employee and silently erasing attribution from
   * real acceptances. A later email change does not rewrite history, which for
   * an audit trail is correct behaviour rather than a defect.
   *
   * Scanners never supply it — `reconcileFinding` refuses one from an adapter,
   * exactly as it refuses a `statusReason`.
   */
  statusChangedBy?: string;
```

- [x] **Step 4: Thread it through both `reconcileFinding` paths**

In `src/lib/security/lifecycle.ts`, the NEW path (inside `if (!existing)`), directly after `statusChangedAt: undefined,`:

```ts
        // A scanner has no standing to record a human decision.
        statusReason: undefined,
        statusChangedAt: undefined,
        statusChangedBy: undefined,
```

And in the `merged` object, directly after `statusChangedAt: existing.statusChangedAt,`:

```ts
    // A human decision outlives the scan that re-reported the finding. Omitting
    // these three lines silently erases every justification and its author on
    // the next scan.
    statusReason: existing.statusReason,
    statusChangedAt: existing.statusChangedAt,
    statusChangedBy: existing.statusChangedBy,
```

(Update the existing comment's "these two lines" to "these three lines" as shown.)

- [x] **Step 5: Run the tests to verify they pass**

```bash
npx vitest run tests/lifecycle.test.ts
```

Expected: PASS, including the pre-existing `statusReason` tests.

- [x] **Step 6: Run the gate**

```bash
npm run lint && npm run typecheck && npm test
```

Expected: all green.

- [x] **Step 7: Commit**

```bash
git add src/domain/security/finding.ts src/lib/security/lifecycle.ts tests/lifecycle.test.ts
git commit -m "feat: carry the deciding user through the finding lifecycle"
```

---

### Task 2: Persist `statusChangedBy` in both drivers

Migration `004`, the PostgreSQL column plumbing, and contract-suite coverage. The in-memory driver needs no code change — `update` spreads the patch — which is exactly why the shared contract suite is the check that matters.

**Files:**
- Create: `db/migrations/004_status_changed_by.sql`
- Modify: `src/lib/security/repository/postgres-security-finding-repository.ts` (`COLUMNS` ~line 49, `COLUMN_COUNT` ~line 52, `FindingRow` ~line 86, `mapRow` ~line 133, `toParams` ~line 173, `MAX_ROWS_PER_INSERT` comment, `ON CONFLICT` list ~line 393)
- Test: `tests/repository/repository-contract.ts`
- Test: `tests/auth/user-cli.test.ts`

**Interfaces:**
- Consumes: `SecurityFinding.statusChangedBy?: string` (Task 1).
- Produces: `security_findings.status_changed_by TEXT` — nullable, no foreign key. Round-trips through `save`, `saveMany` and `update` in both drivers.

- [x] **Step 1: Write the failing contract assertions**

In `tests/repository/repository-contract.ts`, in the round-trip test, add to the `rich` finding's overrides beside `statusReason` / `statusChangedAt`:

```ts
        statusReason: "Accepted while the vendor patch is in flight.",
        statusChangedAt: "2026-08-08T11:30:00.000Z",
        statusChangedBy: "approver@example.com",
```

Assert it survives the round trip, next to the existing `statusReason` assertion on the reloaded rich finding:

```ts
      expect(stored?.statusChangedBy).toBe("approver@example.com");
```

In the same test's sparse-finding assertions, beside `expect(stored?.statusChangedAt).toBeUndefined();`:

```ts
      expect(stored?.statusChangedBy).toBeUndefined();
```

In the manual-decision update test, extend the two `update` calls and their assertions:

```ts
      const accepted = await repository.update(target!.id, {
        status: "ACCEPTED_RISK",
        statusReason: "Compensating control documented in RISK-88.",
        statusChangedAt: "2026-08-11T08:00:00.000Z",
        statusChangedBy: "approver@example.com",
      });
      expect(accepted?.statusChangedBy).toBe("approver@example.com");

      const reloaded = await repository.findByFingerprint("a");
      expect(reloaded?.statusChangedBy).toBe("approver@example.com");
```

and, on the reopen half of that test:

```ts
      const reopened = await repository.update(target!.id, {
        status: "OPEN",
        statusReason: undefined,
        statusChangedAt: "2026-08-12T08:00:00.000Z",
        statusChangedBy: undefined,
      });
      expect(reopened?.statusChangedBy).toBeUndefined();
      expect(
        (await repository.findByFingerprint("a"))?.statusChangedBy,
      ).toBeUndefined();
```

- [x] **Step 2: Run the contract suite to verify it fails**

```bash
npx vitest run tests/repository
```

Expected: the in-memory suite passes (it spreads the patch), the PostgreSQL suite FAILS — `statusChangedBy` is `undefined` after a reload because no column stores it. If the PostgreSQL suite skips, `TEST_DATABASE_URL` is not exported; export it and re-run.

- [x] **Step 3: Write the migration**

Create `db/migrations/004_status_changed_by.sql`:

```sql
-- Who made a manual status decision.
--
-- 002 deliberately left this out: the application had no user authentication,
-- so any attribution stored here would have been fabricated. Accounts arrived
-- with 003, so a decision can now be signed.
--
-- TEXT, not a foreign key to users(id). A risk acceptance is an audit record
-- that must survive the person leaving, and a reference forces a choice between
-- ON DELETE RESTRICT — a departed employee can never be deleted — and
-- ON DELETE SET NULL, which silently erases attribution from real acceptances.
-- A snapshot of the email at the moment of the decision avoids the question.
-- The cost is that a later email change does not rewrite history, which for an
-- audit trail is the correct behaviour.
--
-- Nullable: every finding predating this migration has no author, and a
-- scanner-driven status never sets one.

ALTER TABLE security_findings
  ADD COLUMN IF NOT EXISTS status_changed_by TEXT;
```

- [x] **Step 4: Plumb the column through the PostgreSQL repository**

Five edits in `src/lib/security/repository/postgres-security-finding-repository.ts`. The order of `COLUMNS` and of `toParams` must stay identical — they are positional.

`COLUMNS`:

```ts
  status_reason, status_changed_at, status_changed_by,
```

`COLUMN_COUNT`:

```ts
const COLUMN_COUNT = 36;
```

`FindingRow`, after `status_changed_at`:

```ts
  status_changed_at: Date | null;
  status_changed_by: string | null;
```

`mapRow`, after `statusChangedAt`:

```ts
    statusChangedAt: iso(row.status_changed_at),
    statusChangedBy: undef(row.status_changed_by),
```

`toParams`, after `finding.statusChangedAt ?? null,`:

```ts
    finding.statusChangedAt ?? null,
    finding.statusChangedBy ?? null,
```

The `ON CONFLICT (fingerprint) DO UPDATE` list, after `status_changed_at = EXCLUDED.status_changed_at,`:

```sql
             status_changed_by = EXCLUDED.status_changed_by,
```

And the batching comment above `MAX_ROWS_PER_INSERT`, which quotes the column count:

```ts
/**
 * Postgres caps a statement at 65535 bound parameters. At 36 columns per row
 * that is ~1820 rows; chunk well below it so a large Trivy image report cannot
 * fail on batch size alone.
 */
```

- [x] **Step 5: Apply the migration to the test database and re-run**

```bash
npx vitest run tests/repository
```

Expected: PASS for both drivers. `tests/helpers/postgres.ts` reads every file in `db/migrations/`, so `004` is applied to the scoped test schema automatically — no helper edit.

- [x] **Step 6: Write the offboarding test**

This is what the whole foreign-key decision was made for. In `tests/auth/user-cli.test.ts`, inside the existing `describe("user CLI", …)`:

```ts
    it("deletes a user without disturbing the decisions they signed", async () => {
      await cli(["create", "leaver@example.com", "--role", "approver"]);

      // A decision the departing user signed. Only the NOT NULL columns plus
      // the attribution are needed to make the point.
      await pool.query(
        `INSERT INTO security_findings
           (fingerprint, id, scanner, category, severity, title, status,
            first_detected_at, last_detected_at, status_reason, status_changed_by)
         VALUES ('fp_offboard', 'fnd_offboard', 'SEMGREP', 'SAST', 'HIGH',
                 'SQL injection', 'ACCEPTED_RISK', now(), now(),
                 'Compensating control documented in RISK-88.',
                 'leaver@example.com')`,
      );

      await cli(["delete", "leaver@example.com"]);

      const users = await pool.query(
        `SELECT 1 FROM users WHERE email = 'leaver@example.com'`,
      );
      expect(users.rowCount).toBe(0);

      const finding = await pool.query<{ status_changed_by: string }>(
        `SELECT status_changed_by FROM security_findings WHERE id = 'fnd_offboard'`,
      );
      expect(finding.rows[0].status_changed_by).toBe("leaver@example.com");
    });
```

If the CLI's `delete` requires a confirmation flag, read `scripts/user.mjs` and pass whatever the existing delete tests in this file pass — match them exactly rather than inventing an argument.

- [x] **Step 7: Run the auth suite**

```bash
npx vitest run tests/auth
```

Expected: PASS. The insert succeeds and the row survives the delete because there is no foreign key — if this fails with a constraint violation, a `REFERENCES` clause was added to `004`; remove it.

- [x] **Step 8: Run the gate**

```bash
npm run lint && npm run typecheck && npm test
```

- [x] **Step 9: Commit**

```bash
git add db/migrations/004_status_changed_by.sql src/lib/security/repository/postgres-security-finding-repository.ts tests/repository/repository-contract.ts tests/auth/user-cli.test.ts
git commit -m "feat: store who decided a finding's status"
```

---

### Task 3: The service records the deciding email

`setFindingStatus` gains the author. Its optional tail arguments become one options object, because a second optional scalar in front of `now` would make every call site read `undefined, undefined, NOW`.

**Files:**
- Modify: `src/lib/security/services/security-service.ts:307` (`setFindingStatus`)
- Test: `tests/services/finding-status.test.ts`

**Interfaces:**
- Consumes: `SecurityFinding.statusChangedBy` (Task 1), repository persistence (Task 2).
- Produces:

```ts
setFindingStatus(
  id: string,
  status: FindingStatus,
  reason: string | undefined,
  options?: { changedBy?: string; now?: Date },
): Promise<SecurityFinding | null>
```

  Task 5 calls it as `setFindingStatus(id, status, reason, { changedBy: user.email })`.

- [x] **Step 1: Write the failing tests**

Append to `describe("SecurityService.setFindingStatus", …)` in `tests/services/finding-status.test.ts`:

```ts
  it("records who decided, and the next decision replaces the author", async () => {
    await service.setFindingStatus("fnd_1", "ACCEPTED_RISK", "Mitigated.", {
      changedBy: "approver@example.com",
      now: NOW,
    });

    expect((await findings.findById("fnd_1"))?.statusChangedBy).toBe(
      "approver@example.com",
    );

    const reopened = await service.setFindingStatus("fnd_1", "OPEN", undefined, {
      changedBy: "second@example.com",
      now: NOW,
    });

    // statusChangedAt and statusChangedBy describe the same event: the last
    // manual change. Reopening clears the justification but is itself a
    // decision, and it is the reopener's.
    expect(reopened?.statusChangedBy).toBe("second@example.com");
    expect(reopened?.statusReason).toBeUndefined();
  });

  it("records no author when none is supplied", async () => {
    const updated = await service.setFindingStatus(
      "fnd_1",
      "SUPPRESSED",
      "Known noise from the generated client.",
      { now: NOW },
    );

    expect(updated?.statusChangedBy).toBeUndefined();
  });
```

- [x] **Step 2: Run the tests to verify they fail**

```bash
npx vitest run tests/services/finding-status.test.ts
```

Expected: FAIL — TypeScript rejects an object where `now: Date` is expected.

- [x] **Step 3: Change the signature and record the author**

In `src/lib/security/services/security-service.ts`, replace the parameter list and the first line of the body:

```ts
  async setFindingStatus(
    id: string,
    status: FindingStatus,
    reason: string | undefined,
    options: { changedBy?: string; now?: Date } = {},
  ): Promise<SecurityFinding | null> {
    const now = options.now ?? new Date();
    const finding = await this.findings.findById(id);
```

and extend the update at the end of the method:

```ts
    return this.findings.update(id, {
      status,
      resolvedAt: status === "RESOLVED" ? now.toISOString() : undefined,
      // Reopening without a reason clears the old one: a justification written
      // for a status the finding no longer holds reads as a current decision.
      statusReason,
      statusChangedAt: now.toISOString(),
      // Attribution belongs to the change, not to the justification: this is
      // who made the change `statusChangedAt` timestamps.
      statusChangedBy: options.changedBy,
    });
```

Extend the method's doc comment with one line:

```ts
   * `options.changedBy` is the deciding user's email, snapshotted onto the
   * finding. The caller supplies it from the session; the service never guesses.
```

- [x] **Step 4: Update the existing call sites**

In `tests/services/finding-status.test.ts` only: every place `NOW` is passed as the fourth argument becomes `{ now: NOW }`. Mechanically, `, NOW,` → `, { now: NOW },` and `, NOW)` → `, { now: NOW })` within `setFindingStatus(…)` calls.

`src/lib/security/mock/seed-mock-data.ts:173` and `tests/repository/postgres-ingestion.test.ts:137` pass three arguments and need no change. **Do not** give the mock seed a `changedBy`: the seeded decision has no real author, and inventing one is the fabrication this whole design removed.

- [x] **Step 5: Run the tests to verify they pass**

```bash
npx vitest run tests/services/finding-status.test.ts
```

Expected: PASS, including every pre-existing test in the file.

- [x] **Step 6: Run the gate**

```bash
npm run lint && npm run typecheck && npm test
```

Expected: green. `npm run typecheck` is the check that no call site was missed.

- [x] **Step 7: Commit**

```bash
git add src/lib/security/services/security-service.ts tests/services/finding-status.test.ts
git commit -m "feat: record the deciding user on a status change"
```

---

### Task 4: `requireApprover`

The guard. It throws rather than redirecting, because its only caller is a Server Action whose contract is a result object — a redirect thrown inside an action fetched from an open drawer is followed by the fetch, not by the browser.

**Files:**
- Modify: `src/domain/auth/user.ts` (after `toSessionUser`)
- Modify: `src/domain/auth/errors.ts` (after `WeakPasswordError`)
- Modify: `src/lib/auth/guards.ts` (after `requireUser`)
- Test: `tests/auth/require-approver.test.ts`

**Interfaces:**
- Consumes: `SessionUser`, `getSessionUser()`, `AuthDomainError`, `isAuthDomainError` — all shipped in Plan 1.
- Produces:
  - `isApprover(user: Pick<SessionUser, "role">): boolean`
  - `NotAuthenticatedError` with `code === "UNAUTHENTICATED"`, `httpStatus 401`
  - `ForbiddenError` with `code === "FORBIDDEN"`, `httpStatus 403`
  - `requireApprover(): Promise<SessionUser>` — throws one of the two above.

  Task 5 catches both through `isAuthDomainError`; Task 6 keys the sign-in link off the string `"UNAUTHENTICATED"`.

- [x] **Step 1: Write the failing test**

Create `tests/auth/require-approver.test.ts`:

```ts
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ForbiddenError, NotAuthenticatedError } from "@/domain/auth/errors";
import { SESSION_COOKIE_NAME } from "@/lib/auth/cookie";
import { getAuthService, resetAuthContainer } from "@/lib/auth/container";

/**
 * Exercised against the real in-memory container with only the Next.js cookie
 * jar stubbed. A mocked session store would assert that the guard calls a mock,
 * not that a viewer is refused.
 */

let token: string | undefined;

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) =>
      name === SESSION_COOKIE_NAME && token ? { value: token } : undefined,
  }),
}));

const PASSWORD = "correct horse battery staple";

describe("requireApprover", () => {
  beforeEach(async () => {
    process.env.SECURITY_STORAGE = "memory";
    resetAuthContainer();
    token = undefined;

    const service = await getAuthService();
    await service.createUser("approver@example.com", PASSWORD, "APPROVER");
    await service.createUser("viewer@example.com", PASSWORD, "VIEWER");
  });

  afterEach(() => {
    resetAuthContainer();
    delete process.env.SECURITY_STORAGE;
  });

  async function signIn(email: string) {
    ({ token } = await (await getAuthService()).authenticate(email, PASSWORD));
  }

  it("returns the approver", async () => {
    await signIn("approver@example.com");

    const { requireApprover } = await import("@/lib/auth/guards");
    const user = await requireApprover();

    expect(user.email).toBe("approver@example.com");
    expect(user.role).toBe("APPROVER");
    expect(user).not.toHaveProperty("passwordHash");
  });

  it("refuses a viewer", async () => {
    await signIn("viewer@example.com");

    const { requireApprover } = await import("@/lib/auth/guards");
    await expect(requireApprover()).rejects.toBeInstanceOf(ForbiddenError);
  });

  it("refuses a request with no session", async () => {
    const { requireApprover } = await import("@/lib/auth/guards");
    await expect(requireApprover()).rejects.toBeInstanceOf(
      NotAuthenticatedError,
    );
  });

  it("refuses a signed-out token, which is how revocation is real", async () => {
    await signIn("approver@example.com");
    await (await getAuthService()).signOut(token!);

    const { requireApprover } = await import("@/lib/auth/guards");
    await expect(requireApprover()).rejects.toBeInstanceOf(
      NotAuthenticatedError,
    );
  });
});
```

- [x] **Step 2: Run the test to verify it fails**

```bash
npx vitest run tests/auth/require-approver.test.ts
```

Expected: FAIL — `NotAuthenticatedError`, `ForbiddenError` and `requireApprover` do not exist.

- [x] **Step 3: Add the errors**

Append to `src/domain/auth/errors.ts`, before `isAuthDomainError`:

```ts
/**
 * No usable session: absent, expired, revoked, or belonging to a deleted user.
 *
 * A Server Action reports this as a value rather than redirecting. The caller is
 * a fetch from an open drawer, so a redirect would be followed by that fetch and
 * the user would see nothing happen.
 */
export class NotAuthenticatedError extends AuthDomainError {
  readonly code = "UNAUTHENTICATED";
  readonly httpStatus = 401;

  constructor() {
    super("Your session has expired. Sign in again to continue.");
  }
}

/** Signed in, but the role does not permit this. Names no credential. */
export class ForbiddenError extends AuthDomainError {
  readonly code = "FORBIDDEN";
  readonly httpStatus = 403;

  constructor() {
    super("Approver role is required to change a finding's status.");
  }
}
```

- [x] **Step 4: Add `isApprover`**

Append to `src/domain/auth/user.ts`:

```ts
/**
 * Only an approver may change a finding's status.
 *
 * Lives here rather than in a guard so a client component can ask the same
 * question under jsdom without a server runtime — the drawer's `canDecide` and
 * the action's refusal must not be able to drift apart.
 */
export function isApprover(user: Pick<SessionUser, "role">): boolean {
  return user.role === "APPROVER";
}
```

- [x] **Step 5: Add the guard**

In `src/lib/auth/guards.ts`, add one import and extend the existing `SessionUser` import — the file already has `import type { SessionUser } from "@/domain/auth/user";`, which becomes a value import because `isApprover` is a function:

```ts
import { ForbiddenError, NotAuthenticatedError } from "@/domain/auth/errors";
import { isApprover, type SessionUser } from "@/domain/auth/user";
```

Then append:

```ts
/**
 * Require an approver in a Server Action.
 *
 * Throws instead of redirecting like `requireUser`, because an action's caller
 * is a fetch rather than a navigation: the action maps `AuthDomainError` to its
 * `{ ok: false, code, message }` result and the drawer renders it.
 *
 * Not redundant with the UI. `canDecide` decides what renders; a select element
 * is not a security boundary, exactly as the manual-RESOLVED ban is enforced
 * here as well as hidden there.
 */
export async function requireApprover(): Promise<SessionUser> {
  const user = await getSessionUser();
  if (!user) throw new NotAuthenticatedError();
  if (!isApprover(user)) throw new ForbiddenError();
  return user;
}
```

- [x] **Step 6: Run the test to verify it passes**

```bash
npx vitest run tests/auth/require-approver.test.ts
```

Expected: PASS, four tests.

- [x] **Step 7: Run the gate**

```bash
npm run lint && npm run typecheck && npm test
```

- [x] **Step 8: Commit**

```bash
git add src/domain/auth/errors.ts src/domain/auth/user.ts src/lib/auth/guards.ts tests/auth/require-approver.test.ts
git commit -m "feat: add the approver guard"
```

---

### Task 5: The action enforces the role and signs the decision

**Files:**
- Modify: `src/app/dashboard/security/actions.ts`
- Test: `tests/actions/finding-status-action.test.ts`

**Interfaces:**
- Consumes: `requireApprover()` (Task 4), `setFindingStatus(…, { changedBy })` (Task 3).
- Produces: `setFindingStatusAction` unchanged in signature, now returning `code: "UNAUTHENTICATED"` and `code: "FORBIDDEN"` failures. `SetStatusResult` already types `code` as `string`, so `src/lib/security/status-change.ts` needs no edit.

- [x] **Step 1: Write the failing tests**

Rewrite the head of `tests/actions/finding-status-action.test.ts` so every test runs as a real approver, and add the refusal tests. Replace everything from the imports down to the end of `beforeEach` with:

```ts
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  InvalidStatusReasonError,
  InvalidStatusTransitionError,
} from "@/domain/security/errors";
import { SESSION_COOKIE_NAME } from "@/lib/auth/cookie";
import { getAuthService, resetAuthContainer } from "@/lib/auth/container";

/**
 * The security service is mocked — its behaviour has its own suite — but the
 * session is real. Mocking the guard would assert that the action calls a mock,
 * and the property under test is "a viewer cannot change a status".
 */

const setFindingStatus = vi.fn();
let token: string | undefined;

vi.mock("@/lib/security/container", () => ({
  getSecurityService: async () => ({ setFindingStatus }),
}));

vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: (name: string) =>
      name === SESSION_COOKIE_NAME && token ? { value: token } : undefined,
  }),
}));

const { setFindingStatusAction } = await import(
  "@/app/dashboard/security/actions"
);

const PASSWORD = "correct horse battery staple";

async function signIn(email: string) {
  ({ token } = await (await getAuthService()).authenticate(email, PASSWORD));
}

beforeEach(async () => {
  setFindingStatus.mockReset();
  process.env.SECURITY_STORAGE = "memory";
  resetAuthContainer();
  token = undefined;

  const service = await getAuthService();
  await service.createUser("approver@example.com", PASSWORD, "APPROVER");
  await service.createUser("viewer@example.com", PASSWORD, "VIEWER");
  await signIn("approver@example.com");
});

afterEach(() => {
  resetAuthContainer();
  delete process.env.SECURITY_STORAGE;
});
```

Then add these tests to the existing `describe("setFindingStatusAction", …)`:

```ts
  it("signs the decision with the session's email", async () => {
    setFindingStatus.mockResolvedValue({ id: "fnd_1", status: "ACCEPTED_RISK" });

    await setFindingStatusAction("fnd_1", "ACCEPTED_RISK", "Why.");

    expect(setFindingStatus).toHaveBeenCalledWith("fnd_1", "ACCEPTED_RISK", "Why.", {
      changedBy: "approver@example.com",
    });
  });

  it("refuses a viewer before the service is consulted", async () => {
    await signIn("viewer@example.com");

    const result = await setFindingStatusAction("fnd_1", "ACCEPTED_RISK", "Why.");

    expect(result).toEqual({
      ok: false,
      code: "FORBIDDEN",
      message: expect.any(String),
    });
    expect(setFindingStatus).not.toHaveBeenCalled();
  });

  it("refuses a request with no session", async () => {
    token = undefined;

    const result = await setFindingStatusAction("fnd_1", "ACCEPTED_RISK", "Why.");

    expect(result).toEqual({
      ok: false,
      code: "UNAUTHENTICATED",
      message: expect.any(String),
    });
    expect(setFindingStatus).not.toHaveBeenCalled();
  });

  it("refuses a revoked session, so signing out ends the ability to decide", async () => {
    await (await getAuthService()).signOut(token!);

    const result = await setFindingStatusAction("fnd_1", "ACCEPTED_RISK", "Why.");

    expect(result).toMatchObject({ ok: false, code: "UNAUTHENTICATED" });
    expect(setFindingStatus).not.toHaveBeenCalled();
  });
```

- [x] **Step 2: Run the tests to verify they fail**

```bash
npx vitest run tests/actions/finding-status-action.test.ts
```

Expected: FAIL — the action ignores the session entirely, so the viewer and no-session cases reach the service and the `changedBy` assertion sees three arguments.

- [x] **Step 3: Enforce and thread**

Rewrite `src/app/dashboard/security/actions.ts`. The doc comment is stale — it states the application has no user authentication — so it is replaced, not appended to:

```ts
"use server";

import { isAuthDomainError } from "@/domain/auth/errors";
import { isFindingStatus, type FindingStatus } from "@/domain/security/enums";
import { isSecurityDomainError } from "@/domain/security/errors";
import { requireApprover } from "@/lib/auth/guards";
import { getSecurityService } from "@/lib/security/container";
import type { SetStatusResult } from "@/lib/security/status-change";

/**
 * Apply a human decision to a finding.
 *
 * A Server Action rather than a REST route: an endpoint that flips a CRITICAL
 * finding to FALSE_POSITIVE is a direct way to hide a real vulnerability, and
 * the only credential CI holds — SECURITY_INGEST_TOKEN — must never reach a
 * browser.
 *
 * `requireApprover()` runs here regardless of what the drawer rendered. The
 * drawer's `canDecide` only chooses between an enabled and a locked control;
 * a select element is not a security boundary, which is the same reason the
 * manual-RESOLVED ban is enforced below rather than only hidden in the UI.
 *
 * Failures come back as a value, never as a throw. An unexpected error's
 * message can contain an internal hostname or a payload fragment, so only
 * domain errors — which are safe by construction — pass their message through.
 */
export async function setFindingStatusAction(
  id: string,
  status: FindingStatus,
  reason: string | undefined,
): Promise<SetStatusResult> {
  if (!isFindingStatus(status)) {
    return {
      ok: false,
      code: "INVALID_STATUS_TRANSITION",
      message: "That is not a finding status.",
    };
  }

  // The UI withholds manual RESOLVED so mean-time-to-remediate cannot be
  // improved by assertion. Enforced here too: the select element is not a
  // security boundary.
  if (status === "RESOLVED") {
    return {
      ok: false,
      code: "INVALID_STATUS_TRANSITION",
      message: "A finding is resolved by a scan, not by hand.",
    };
  }

  try {
    const user = await requireApprover();

    const service = await getSecurityService();
    const finding = await service.setFindingStatus(id, status, reason, {
      changedBy: user.email,
    });

    if (!finding) {
      return { ok: false, code: "NOT_FOUND", message: "Finding not found." };
    }

    return { ok: true, finding };
  } catch (error) {
    // UNAUTHENTICATED and FORBIDDEN arrive here from requireApprover. Both
    // messages are written to be safe to show a browser.
    if (isAuthDomainError(error) || isSecurityDomainError(error)) {
      return { ok: false, code: error.code, message: error.message };
    }
    return {
      ok: false,
      code: "INTERNAL_ERROR",
      message: "The status change could not be applied.",
    };
  }
}
```

Note the ordering: the two shape checks stay ahead of the session check, so the existing "refuses RESOLVED before the service is consulted" test keeps passing regardless of who is signed in, and a malformed status never costs a session lookup.

- [x] **Step 4: Run the tests to verify they pass**

```bash
npx vitest run tests/actions/finding-status-action.test.ts
```

Expected: PASS — the four new tests plus all seven pre-existing ones.

- [x] **Step 5: Run the gate**

```bash
npm run lint && npm run typecheck && npm test
```

- [x] **Step 6: Commit**

```bash
git add src/app/dashboard/security/actions.ts tests/actions/finding-status-action.test.ts
git commit -m "feat: require an approver to change a finding's status"
```

---

### Task 6: The drawer shows the author and locks a viewer's control

**Files:**
- Modify: `src/components/security/finding-details.tsx`
- Modify: `src/components/security/findings-table.tsx` (props ~line 90, `FindingDetails` usage ~line 480)
- Modify: `src/app/dashboard/security/page.tsx:33` and the `FindingsTable` usage ~line 127
- Test: `tests/components/finding-details.test.tsx`
- Test: `tests/components/findings-table.test.tsx`

**Interfaces:**
- Consumes: `SecurityFinding.statusChangedBy` (Task 1), `isApprover` (Task 4), the `"UNAUTHENTICATED"` code (Task 5).
- Produces: `canDecide?: boolean` on both `FindingDetails` and `FindingsTable`, defaulting to `false`.

- [x] **Step 1: Write the failing component tests**

Add to `tests/components/finding-details.test.tsx`:

```ts
  it("locks the control for a viewer and says why", async () => {
    const onApplyStatus = vi.fn();

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={onApplyStatus}
        canDecide={false}
      />,
    );

    expect(screen.getByLabelText(/change status to/i)).toBeDisabled();
    expect(screen.getByRole("button", { name: /apply/i })).toBeDisabled();
    expect(screen.getByText(/approver role is required/i)).toBeInTheDocument();
    expect(onApplyStatus).not.toHaveBeenCalled();
  });

  it("gives an approver a working control", async () => {
    const onApplyStatus = vi
      .fn()
      .mockResolvedValue({ ok: true, finding: finding({ status: "SUPPRESSED" }) });

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={onApplyStatus}
        onStatusChanged={vi.fn()}
        canDecide
      />,
    );

    const user = userEvent.setup();
    await user.selectOptions(screen.getByLabelText(/change status to/i), "SUPPRESSED");
    await user.type(screen.getByLabelText(/reason/i), "Known noise.");
    await user.click(screen.getByRole("button", { name: /apply/i }));

    await waitFor(() =>
      expect(onApplyStatus).toHaveBeenCalledWith("fnd_1", "SUPPRESSED", "Known noise."),
    );
  });

  it("shows who signed a decision", () => {
    render(
      <FindingDetails
        finding={finding({
          status: "ACCEPTED_RISK",
          statusReason: "Compensating control documented in RISK-88.",
          statusChangedAt: "2026-08-11T08:00:00.000Z",
          statusChangedBy: "approver@example.com",
        })}
        onClose={() => {}}
      />,
    );

    expect(screen.getByText(/approver@example\.com/)).toBeInTheDocument();
  });

  it("offers a way back in when the session expired mid-decision", async () => {
    const onApplyStatus = vi.fn().mockResolvedValue({
      ok: false,
      code: "UNAUTHENTICATED",
      message: "Your session has expired. Sign in again to continue.",
    });

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={onApplyStatus}
        canDecide
      />,
    );

    const user = userEvent.setup();
    await user.selectOptions(screen.getByLabelText(/change status to/i), "SUPPRESSED");
    await user.type(screen.getByLabelText(/reason/i), "Known noise.");
    await user.click(screen.getByRole("button", { name: /apply/i }));

    const link = await screen.findByRole("link", { name: /sign in/i });
    expect(link).toHaveAttribute("href", "/login");
  });
```

Every pre-existing test in this file that passes `onApplyStatus` and expects a working control must gain `canDecide` — the default is `false`, deliberately, so that a caller which never asked who is looking gets the locked control.

In `tests/components/findings-table.test.tsx`, the existing test `"refetches the current query and refreshes the page after a status change"` renders with `setStatusAction` and drives the form, so it must gain `canDecide` too:

```tsx
      <FindingsTable
        initialResult={initialResult}
        filterOptions={filterOptions}
        setStatusAction={setStatusAction}
        canDecide
      />
```

Then add a test that the flag actually reaches the drawer, matching that file's pattern of clicking a finding's title to open it:

```tsx
  it("passes the decision permission down to the drawer", async () => {
    const user = userEvent.setup();

    const { unmount } = render(
      <FindingsTable
        initialResult={initialResult}
        filterOptions={filterOptions}
        setStatusAction={vi.fn()}
      />,
    );

    await user.click(screen.getByText("Hardcoded AWS access key"));
    // No canDecide: a caller that did not ask the guard gets the locked control.
    expect(screen.getByLabelText(/change status to/i)).toBeDisabled();

    unmount();

    render(
      <FindingsTable
        initialResult={initialResult}
        filterOptions={filterOptions}
        setStatusAction={vi.fn()}
        canDecide
      />,
    );

    await user.click(screen.getByText("Hardcoded AWS access key"));
    expect(screen.getByLabelText(/change status to/i)).toBeEnabled();
  });
```

- [x] **Step 2: Run the tests to verify they fail**

```bash
npx vitest run tests/components
```

Expected: FAIL — `canDecide` is not a prop.

- [x] **Step 3: Update `FindingDetails`**

Props:

```ts
export function FindingDetails({
  finding,
  onClose,
  onApplyStatus,
  onStatusChanged,
  canDecide = false,
}: {
  finding: SecurityFinding;
  onClose: () => void;
  /** Absent in read-only contexts; the decision form is then not rendered. */
  onApplyStatus?: SetFindingStatusAction;
  onStatusChanged?: (finding: SecurityFinding) => void;
  /**
   * Whether the signed-in user may decide. Defaults to `false`: this component
   * cannot know who is looking, so a caller that did not ask the guard gets the
   * locked control. The action re-checks regardless.
   */
  canDecide?: boolean;
}) {
```

The attribution line inside the Decision section — replace the `statusChangedAt` paragraph:

```tsx
                  {(finding.statusChangedAt || finding.statusChangedBy) && (
                    <p className="text-ink-faint mt-1.5 font-mono text-[10px]">
                      {statusLabel(finding.status)}
                      {finding.statusChangedAt &&
                        ` · ${formatDateTime(finding.statusChangedAt)}`}
                      {finding.statusChangedBy && ` · ${finding.statusChangedBy}`}
                    </p>
                  )}
```

And pass the flag down:

```tsx
              {onApplyStatus && (
                <DecisionForm
                  finding={finding}
                  onApplyStatus={onApplyStatus}
                  onStatusChanged={onStatusChanged}
                  locked={!canDecide}
                />
              )}
```

- [x] **Step 4: Update `DecisionForm`**

Signature and state:

```tsx
function DecisionForm({
  finding,
  onApplyStatus,
  onStatusChanged,
  locked,
}: {
  finding: SecurityFinding;
  onApplyStatus: SetFindingStatusAction;
  onStatusChanged?: (finding: SecurityFinding) => void;
  /** A viewer sees the control it cannot use, and the reason, rather than nothing. */
  locked: boolean;
}) {
  const targets = selectableTransitions(finding.status);
  const [target, setTarget] = useState<FindingStatus | "">("");
  const [reason, setReason] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<{ code: string; message: string } | undefined>();
```

Submit guard and error capture:

```tsx
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (locked || !target || pending) return;

    setPending(true);
    setError(undefined);

    const result = await onApplyStatus(
      finding.id,
      target,
      reason.trim() === "" ? undefined : reason,
    );

    setPending(false);

    if (!result.ok) {
      setError({ code: result.code, message: result.message });
      return;
    }

    setReason("");
    setTarget("");
    onStatusChanged?.(result.finding);
  };
```

Disable the three controls — `disabled={pending}` becomes `disabled={pending || locked}` on the `select` and the `textarea`, and the submit button becomes:

```tsx
      <button
        type="submit"
        disabled={pending || locked || target === ""}
        className="border-line text-ink-muted hover:border-line-strong hover:text-ink rounded border px-2.5 py-1 font-mono text-[11px] transition-colors disabled:cursor-not-allowed disabled:opacity-40"
      >
        {pending ? "Applying…" : "Apply"}
      </button>
```

The explanation, rendered in place of the error slot when locked:

```tsx
      {locked && (
        <p className="text-ink-faint text-xs leading-relaxed">
          Approver role is required to change a finding&rsquo;s status. Every
          justification already recorded is visible above.
        </p>
      )}

      {error && (
        <p role="alert" className="text-fail text-xs">
          {error.message}{" "}
          {error.code === "UNAUTHENTICATED" && (
            <a href="/login" className="text-accent underline">
              Sign in
            </a>
          )}
        </p>
      )}
```

The sign-in link is a plain `<a>`, not a `next/link`: an expired session needs a full document load so the server can redirect and set a fresh cookie.

- [x] **Step 5: Pass the flag through the table and the page**

`src/components/security/findings-table.tsx` — add to the destructured props and the type:

```ts
export function FindingsTable({
  initialResult,
  filterOptions,
  initialSelected,
  initialState = DEFAULT_QUERY_STATE,
  setStatusAction,
  canDecide = false,
}: {
```

```ts
  setStatusAction?: SetFindingStatusAction;
  /** Approver-only. Defaults to `false`; the action re-checks regardless. */
  canDecide?: boolean;
}) {
```

and at the `FindingDetails` usage:

```tsx
        <FindingDetails
          finding={selected}
          onClose={() => setSelected(null)}
          onApplyStatus={setStatusAction}
          onStatusChanged={handleStatusChanged}
          canDecide={canDecide}
        />
```

`src/app/dashboard/security/page.tsx` — capture the user the page already requires, and pass the answer:

```tsx
import { isApprover } from "@/domain/auth/user";
```

```tsx
  // Layouts do not re-run on every client-side navigation, so the layout check
  // is a redirect rather than a gate. This is the gate — and the page needs the
  // user anyway, to decide whether the decision control is usable.
  const user = await requireUser();
```

```tsx
        <FindingsTable
          initialResult={firstPage}
          filterOptions={filterOptions}
          initialSelected={selectedFinding}
          setStatusAction={setFindingStatusAction}
          canDecide={isApprover(user)}
        />
```

- [x] **Step 6: Run the tests to verify they pass**

```bash
npx vitest run tests/components
```

Expected: PASS.

- [x] **Step 7: Run the gate**

```bash
npm run lint && npm run typecheck && npm test
```

- [x] **Step 8: Commit**

```bash
git add src/components/security/finding-details.tsx src/components/security/findings-table.tsx src/app/dashboard/security/page.tsx tests/components
git commit -m "feat: show a decision's author and lock a viewer's control"
```

---

### Task 7: Documentation and the full verification pass

**Files:**
- Modify: `README.md` (authentication section; "Known limitations" ~line 690)
- Modify: `docs/superpowers/plans/2026-08-08-dashboard-authentication-roles.md` (this file — tick the boxes)
- Modify: `docs/superpowers/specs/2026-08-08-dashboard-authentication-design.md` (status line)
- Modify: `CLAUDE.md` (the invariants list)

**Interfaces:**
- Consumes: everything above.
- Produces: no code.

- [x] **Step 1: Update the README**

Three edits, all replacing text that is now false.

In `### Manual decisions`, replace the closing paragraph:

```markdown
No actor is recorded. There is no user authentication to derive one from, and a
stored `changedBy` would be fabricated attribution.
```

with:

```markdown
The deciding account's email is recorded in `statusChangedBy`, snapshotted at
the moment of the decision rather than joined through a foreign key: a risk
acceptance is an audit record that has to survive the person leaving. Deleting
an account therefore leaves every decision it signed intact, and a later email
change does not rewrite history. `reconcileFinding` carries it exactly as it
carries the justification — restored on the merge path, cleared on the NEW path.

Only an `APPROVER` may decide. A viewer sees the control disabled with the
reason, and `setFindingStatusAction` re-checks the role regardless of what the
drawer rendered.
```

Replace the whole `### Roles` section body:

```markdown
### Roles

Accounts are `VIEWER` or `APPROVER`.

| | Read the dashboard and every recorded justification | Change a finding's status |
|---|---|---|
| `VIEWER` | yes | no |
| `APPROVER` | yes | yes |

The split exists because developers need to see their own findings without
being able to dismiss them.

The role is chosen at provisioning and changed afterwards:

```bash
npm run user -- create alice@example.com --role approver
npm run user -- role alice@example.com viewer
```

Enforcement is in the Server Action (`requireApprover()`), not in the UI. The
drawer's disabled control is a courtesy; a crafted request meets the same
refusal, the same way manual `RESOLVED` is refused there rather than only
hidden.
```

In "Known limitations", **delete** this entry — it is now false:

```markdown
- Roles are recorded but not yet enforced: any signed-in account can change a
  finding's status, and no author is recorded on the decision. Both land with
  the second half of the authentication work.
```

Leave the other limitations alone. Do not add a new one: this plan closes a gap rather than opening one.

- [x] **Step 2: Update `CLAUDE.md`**

Invariant 4 currently reads:

```markdown
4. **`firstDetectedAt` is never overwritten**, and `ACCEPTED_RISK` /
   `FALSE_POSITIVE` / `SUPPRESSED` are never auto-changed by a scan.
```

Extend it so the next reader does not reintroduce the bug this plan guards:

```markdown
4. **`firstDetectedAt` is never overwritten**, and `ACCEPTED_RISK` /
   `FALSE_POSITIVE` / `SUPPRESSED` are never auto-changed by a scan.
   `statusReason` / `statusChangedAt` / `statusChangedBy` are restored from the
   stored finding on the merge path and cleared on the NEW path — dropping the
   first lets a scan erase attribution, dropping the second lets an adapter
   forge one.
```

Also update the storage section's test count once the final run reports it.

- [x] **Step 3: Mark the spec and this plan complete**

In the spec, change `**Status:** designed, not yet implemented` to `**Status:** implemented (plan 1 2026-08-08, plan 2 2026-08-08)`.

In this plan, tick every checkbox that has been completed.

- [x] **Step 4: Run the full gate, including the build**

```bash
npm run lint && npm run typecheck && npm test && npm run build
```

Expected: green, with `TEST_DATABASE_URL` exported so the PostgreSQL suites run rather than skip. Record the test count.

- [x] **Step 5: Live verification in the dev server**

Start the dev server (`.claude/launch.json` has `"autoPort": true`, so it will not be on 3000 — read the reported port) and check all six:

1. Sign in as the seeded dev approver; the drawer's decision control is enabled.
2. Accept a risk with a justification; the drawer shows the reason, the timestamp and the signing email.
3. `GET /api/security/findings?...` for that finding returns `statusChangedBy` with the same email.
4. Provision a viewer (`npm run user -- create viewer@localhost --role viewer`, Postgres only — against the memory driver, change the seeded account's role in the seed instead), sign in as it, and confirm the control is disabled with the "Approver role is required" explanation.
5. Sign out in a second tab, then submit a decision in the first: the drawer shows the expiry message with a working Sign in link.
6. Run a scan ingestion (`POST /api/security/scans`) that re-reports the accepted finding, and confirm the email and the justification survive it.

- [x] **Step 6: Commit**

```bash
git add README.md CLAUDE.md docs/superpowers
git commit -m "docs: document roles and decision attribution"
```

---

## Out of scope — do not add

Named here because each is a plausible-looking next step the spec ruled out:

- SSO, OIDC, password reset, self-signup, or an admin UI. The CLI is the admin surface.
- Per-repository or per-application authorization scopes.
- A third role, or a permission table. Two roles, one decision.
- A foreign key from `security_findings` to `users`, or any backfill of `status_changed_by` for decisions made before this plan. Those decisions genuinely had no author.
- Attribution on scanner-driven transitions (auto-resolve, reopen-by-scan). No person made those.
- Rate limiting on scan ingestion — still its own known limitation.
