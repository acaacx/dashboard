# Manual Finding Status Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a person mark a security finding as accepted risk, false positive or suppressed from the finding detail drawer, recording why they decided that.

**Architecture:** The service already implements the decision and its transition table; this plan adds two domain fields carrying the justification, a Next.js Server Action as the write path (no public REST route, no credential in the browser), and a decision form in the existing detail drawer. The action is passed from the server page down through `FindingsTable` into `FindingDetails` as a prop, so component tests inject a plain stub instead of booting a server runtime.

**Tech Stack:** Next.js 16 App Router, React 19, TypeScript strict, Tailwind v4, Zod, Vitest + Testing Library, `pg`.

## Global Constraints

Copied from `CLAUDE.md` and the spec. Every task inherits these.

- **Components never see scanner output.** `src/components/` receives `SecurityFinding` objects and pre-computed statistics only.
- **Secrets are never stored.** No new field may carry scanner match text.
- **`firstDetectedAt` is never overwritten**, and `ACCEPTED_RISK` / `FALSE_POSITIVE` / `SUPPRESSED` are never auto-changed by a scan.
- **Fingerprints exclude** timestamps, severity, status, description, commit and branch. Neither new field enters the fingerprint.
- **No `dangerouslySetInnerHTML`.** `statusReason` is rendered as JSX text.
- **Metric definitions live in the service/repository**, never in a chart.
- **Migrations are forward-only.** Add a new numbered file; never edit an applied one.
- **Port 5432 on this machine is an SSH tunnel.** Local Postgres containers use **5433**.
- **`npm run typecheck` runs `next typegen` first.** Bare `tsc --noEmit` fails on `PageProps`/`LayoutProps`.
- **Component tests must wait for the expected query**, not read the last fetch call — filters are debounced 200 ms.
- Reason length limit: **500 characters**.
- Baseline before starting: `main` at `608c5c7`, 272 tests without a database, 323 with one, lint/typecheck/build clean.

Database for the full suite:

```bash
docker run -d --name dashboard-test-pg -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=dashboard_test -p 5433:5432 postgres:17-alpine
```

Then in every shell that runs tests:

```bash
export TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test
```

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `src/lib/security/status-change.ts` | Shared, dependency-light contract between server action and client components: result type, action type, the UI transition policy, the length limit. No `"use server"`, no zod, so it is safe to import from a client component. |
| `src/app/dashboard/security/actions.ts` | The Server Action. Translates thrown domain errors into a discriminated result. |
| `db/migrations/002_finding_status_reason.sql` | Two nullable columns. |
| `tests/services/finding-status.test.ts` | Service behaviour for `setFindingStatus`. |
| `tests/actions/finding-status-action.test.ts` | Error mapping and the server-side `RESOLVED` rejection. |
| `tests/components/finding-details.test.tsx` | Drawer decision form. |

**Modified:**

| File | Change |
|---|---|
| `src/domain/security/finding.ts` | Two optional fields. |
| `src/domain/security/errors.ts` | Two error classes. |
| `src/lib/security/lifecycle.ts` | Preserve the new fields through `reconcileFinding`. |
| `src/lib/security/validation/schemas.ts` | `statusReasonSchema`. |
| `src/lib/security/services/security-service.ts` | `setFindingStatus` gains the reason. |
| `src/lib/security/repository/postgres-security-finding-repository.ts` | Columns, row type, mappers, upsert. |
| `src/components/security/finding-details.tsx` | Decision section. |
| `src/components/security/findings-table.tsx` | Refresh wiring, action pass-through. |
| `src/app/dashboard/security/page.tsx` | Pass the action down. |
| `tests/lifecycle.test.ts` | Preservation tests. |
| `tests/repository/repository-contract.ts` | Round-trip and NULL assertions. |
| `tests/repository/postgres-ingestion.test.ts` | Existing `setFindingStatus` call gains a reason argument. |
| `tests/helpers/postgres.ts` | Reads every migration, not just `001_init.sql`. |
| `tests/components/findings-table.test.tsx` | `next/navigation` mock, refresh test. |
| `README.md` | Lifecycle, schema, limitations, test counts. |

The in-memory repository needs **no change**: `update` spreads the patch over the stored object and the store holds whole `SecurityFinding` values, so both new fields round-trip already. Do not add code there.

---

## Task 1: Domain fields and lifecycle preservation

The highest-risk change in the whole plan. `reconcileFinding` spreads `...incoming` over the existing finding and then restores history fields one at a time. If the two new fields are not on that restore list, the next scan erases every justification in the database.

**Files:**
- Modify: `src/domain/security/finding.ts:79` (after `resolvedAt`)
- Modify: `src/lib/security/lifecycle.ts:79-115`
- Test: `tests/lifecycle.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `SecurityFinding.statusReason?: string`, `SecurityFinding.statusChangedAt?: string`. Every later task depends on these two names.

- [ ] **Step 1: Write the failing tests**

Append to `tests/lifecycle.test.ts`:

```ts
describe("reconcileFinding and human decisions", () => {
  it("preserves a recorded justification when a scan sees the finding again", () => {
    const existing = finding({
      status: "ACCEPTED_RISK",
      statusReason: "Compensating control in the WAF, reviewed 2026-08-01.",
      statusChangedAt: "2026-08-01T09:00:00.000Z",
    });

    const { finding: merged, transition } = reconcileFinding(
      existing,
      finding({ lastDetectedAt: "2026-08-12T00:00:00.000Z" }),
    );

    expect(transition).toBe("EXISTING");
    expect(merged.status).toBe("ACCEPTED_RISK");
    expect(merged.statusReason).toBe(
      "Compensating control in the WAF, reviewed 2026-08-01.",
    );
    expect(merged.statusChangedAt).toBe("2026-08-01T09:00:00.000Z");
  });

  it("preserves the justification when a resolved finding is reopened by a scan", () => {
    const existing = finding({
      status: "RESOLVED",
      resolvedAt: "2026-08-05T00:00:00.000Z",
      statusReason: "Marked false positive in July, later reopened.",
      statusChangedAt: "2026-07-02T09:00:00.000Z",
    });

    const { finding: merged, transition } = reconcileFinding(
      existing,
      finding({ lastDetectedAt: "2026-08-12T00:00:00.000Z" }),
    );

    expect(transition).toBe("REOPENED");
    expect(merged.status).toBe("OPEN");
    expect(merged.statusReason).toBe(
      "Marked false positive in July, later reopened.",
    );
    expect(merged.statusChangedAt).toBe("2026-07-02T09:00:00.000Z");
  });

  it("does not invent a justification for a finding nobody ruled on", () => {
    const { finding: merged } = reconcileFinding(
      undefined,
      finding({ statusReason: "scanner supplied this", statusChangedAt: "x" }),
    );

    expect(merged.statusReason).toBeUndefined();
    expect(merged.statusChangedAt).toBeUndefined();
  });
});
```

The third test matters: a scanner adapter must never be able to plant a justification. `reconcileFinding` receives `incoming` built by an adapter, and the NEW branch currently spreads `...incoming` wholesale.

`tests/lifecycle.test.ts` already has a local `finding()` helper — reuse it, do not define another. Confirm its name with `grep -n "function finding" tests/lifecycle.test.ts` before writing.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npx vitest run tests/lifecycle.test.ts
```

Expected: the first two fail on `undefined` not matching the reason; the third may pass by accident depending on the helper. TypeScript will also complain that `statusReason` is not a property of `SecurityFinding` — that is the expected first failure.

- [ ] **Step 3: Add the domain fields**

In `src/domain/security/finding.ts`, directly after `resolvedAt?: string;`:

```ts
  /**
   * Why a human set the current status. Present only when a person decided:
   * scanners never supply it and `reconcileFinding` refuses to accept one from
   * an adapter. Free text, untrusted, rendered as text and never as HTML.
   */
  statusReason?: string;

  /** ISO-8601 UTC instant of the last manual status change. */
  statusChangedAt?: string;
```

- [ ] **Step 4: Preserve the fields in reconcileFinding**

In `src/lib/security/lifecycle.ts`, the NEW branch (currently lines 55-64) must strip anything an adapter supplied:

```ts
  if (!existing) {
    return {
      finding: {
        ...incoming,
        status: incoming.status === "SUPPRESSED" ? "SUPPRESSED" : "OPEN",
        firstDetectedAt: incoming.firstDetectedAt,
        lastDetectedAt: incoming.lastDetectedAt,
        // A scanner has no standing to record a human decision.
        statusReason: undefined,
        statusChangedAt: undefined,
      },
      transition: "NEW",
    };
  }
```

And the `merged` object (currently lines 79-90) gains two entries in its "stable identity and history" group, immediately after `resolvedAt`:

```ts
    status: existing.status,
    resolvedAt: existing.resolvedAt,
    // A human decision outlives the scan that re-reported the finding. Omitting
    // these two lines silently erases every justification on the next scan.
    statusReason: existing.statusReason,
    statusChangedAt: existing.statusChangedAt,
    metadata: { ...existing.metadata, ...incoming.metadata },
```

The REOPENED branch spreads `...merged`, so it inherits both fields with no further change.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
npx vitest run tests/lifecycle.test.ts
```

Expected: PASS, all three new tests plus every pre-existing one.

- [ ] **Step 6: Commit**

```bash
git add src/domain/security/finding.ts src/lib/security/lifecycle.ts tests/lifecycle.test.ts
git commit -m "feat: carry a human justification on a finding

statusReason and statusChangedAt record why somebody set a status.
reconcileFinding restores both from the stored finding, alongside status
and resolvedAt: without that, the next scan erases every justification.
A scanner cannot plant one, because the NEW branch clears whatever the
adapter supplied.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 2: Shared status-change contract

A dependency-light module both the Server Action and the client components import. It exists so the UI's "no manual RESOLVED" policy is written once and enforced on the server, not just rendered in a `<select>`.

**Files:**
- Create: `src/lib/security/status-change.ts`
- Test: covered by Tasks 3-6; no test of its own (it is four declarations and one three-line function, exercised by every task that follows)

**Interfaces:**
- Consumes: `canTransition` from `src/lib/security/lifecycle.ts`, `FINDING_STATUSES` and `FindingStatus` from `src/domain/security/enums.ts`, `SecurityFinding` from `src/domain/security/finding.ts`.
- Produces:
  - `MAX_STATUS_REASON_LENGTH: 500`
  - `selectableTransitions(from: FindingStatus): FindingStatus[]`
  - `type SetStatusResult = { ok: true; finding: SecurityFinding } | { ok: false; code: string; message: string }`
  - `type SetFindingStatusAction = (id: string, status: FindingStatus, reason: string | undefined) => Promise<SetStatusResult>`

- [ ] **Step 1: Write the module**

```ts
import { FINDING_STATUSES, type FindingStatus } from "@/domain/security/enums";
import type { SecurityFinding } from "@/domain/security/finding";
import { canTransition } from "./lifecycle";

/**
 * The contract shared by the status-change Server Action and the components
 * that call it.
 *
 * Deliberately free of zod, `pg` and `"use server"`: a client component imports
 * it, and a component test imports it under jsdom without booting a server
 * runtime.
 */

/** Longest justification accepted. Long enough for a real risk acceptance. */
export const MAX_STATUS_REASON_LENGTH = 500;

/**
 * Statuses the UI offers, given where a finding is now.
 *
 * `canTransition` permits OPEN -> RESOLVED. This deliberately does not: RESOLVED
 * means a scan stopped seeing the finding, and letting a person assert it by
 * hand turns mean-time-to-remediate into a number anyone can improve without
 * fixing anything. The service still permits it — the restriction is policy at
 * this boundary, and the Server Action enforces it so a crafted request cannot
 * route around the select element.
 */
export function selectableTransitions(from: FindingStatus): FindingStatus[] {
  return FINDING_STATUSES.filter(
    (to) => to !== from && to !== "RESOLVED" && canTransition(from, to),
  );
}

/**
 * Result of a status change. The action returns this rather than throwing, so
 * an unexpected failure cannot deliver a stack trace or an internal path to the
 * browser.
 */
export type SetStatusResult =
  | { ok: true; finding: SecurityFinding }
  | { ok: false; code: string; message: string };

export type SetFindingStatusAction = (
  id: string,
  status: FindingStatus,
  reason: string | undefined,
) => Promise<SetStatusResult>;
```

- [ ] **Step 2: Verify it compiles**

```bash
npm run typecheck
```

Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/lib/security/status-change.ts
git commit -m "feat: add the shared status-change contract

One place for the transition policy the UI offers, the result shape the
Server Action returns, and the reason length limit. Free of zod and pg so
a client component and a jsdom test can import it.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 3: Service accepts and validates a reason

**Files:**
- Modify: `src/domain/security/errors.ts` (append before `isSecurityDomainError`)
- Modify: `src/lib/security/validation/schemas.ts`
- Modify: `src/lib/security/services/security-service.ts:294-316`
- Modify: `tests/repository/postgres-ingestion.test.ts:137`
- Test: `tests/services/finding-status.test.ts` (create)

**Interfaces:**
- Consumes: `statusReason` / `statusChangedAt` (Task 1), `MAX_STATUS_REASON_LENGTH` (Task 2), `isHumanDecided` from `src/lib/security/lifecycle.ts`.
- Produces:
  - `InvalidStatusTransitionError` — `code: "INVALID_STATUS_TRANSITION"`, `httpStatus: 409`
  - `InvalidStatusReasonError` — `code: "INVALID_STATUS_REASON"`, `httpStatus: 400`
  - `SecurityService.setFindingStatus(id: string, status: FindingStatus, reason: string | undefined, now?: Date): Promise<SecurityFinding | null>`

- [ ] **Step 1: Write the failing tests**

Create `tests/services/finding-status.test.ts`:

```ts
import { beforeEach, describe, expect, it } from "vitest";

import {
  InvalidStatusReasonError,
  InvalidStatusTransitionError,
} from "@/domain/security/errors";
import type { SecurityFinding } from "@/domain/security/finding";
import { InMemorySecurityFindingRepository } from "@/lib/security/repository/memory-security-finding-repository";
import { SecurityService } from "@/lib/security/services/security-service";

const NOW = new Date("2026-08-12T10:00:00.000Z");

function open(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: "fnd_1",
    fingerprint: "fp1",
    scanner: "SEMGREP",
    category: "SAST",
    severity: "HIGH",
    title: "SQL injection",
    repositoryName: "payment-service",
    status: "OPEN",
    firstDetectedAt: "2026-08-01T00:00:00.000Z",
    lastDetectedAt: "2026-08-10T00:00:00.000Z",
    ...overrides,
  };
}

let findings: InMemorySecurityFindingRepository;
let service: SecurityService;

beforeEach(async () => {
  findings = new InMemorySecurityFindingRepository();
  service = new SecurityService(findings);
  await findings.save(open());
});

describe("SecurityService.setFindingStatus", () => {
  it("records the reason and the moment of the decision", async () => {
    const updated = await service.setFindingStatus(
      "fnd_1",
      "ACCEPTED_RISK",
      "  Mitigated by the WAF rule shipped in PR 412.  ",
      NOW,
    );

    expect(updated?.status).toBe("ACCEPTED_RISK");
    expect(updated?.statusReason).toBe(
      "Mitigated by the WAF rule shipped in PR 412.",
    );
    expect(updated?.statusChangedAt).toBe("2026-08-12T10:00:00.000Z");
  });

  it("requires a reason for every human-decided status", async () => {
    for (const status of ["ACCEPTED_RISK", "FALSE_POSITIVE", "SUPPRESSED"] as const) {
      await expect(
        service.setFindingStatus("fnd_1", status, undefined, NOW),
      ).rejects.toBeInstanceOf(InvalidStatusReasonError);
    }
  });

  it("treats a whitespace-only reason as missing", async () => {
    await expect(
      service.setFindingStatus("fnd_1", "ACCEPTED_RISK", "   \n ", NOW),
    ).rejects.toBeInstanceOf(InvalidStatusReasonError);
  });

  it("rejects a reason longer than the limit", async () => {
    await expect(
      service.setFindingStatus("fnd_1", "ACCEPTED_RISK", "x".repeat(501), NOW),
    ).rejects.toBeInstanceOf(InvalidStatusReasonError);
  });

  it("clears a stale justification when a finding is reopened without one", async () => {
    await service.setFindingStatus("fnd_1", "FALSE_POSITIVE", "Test fixture.", NOW);

    const reopened = await service.setFindingStatus(
      "fnd_1",
      "OPEN",
      undefined,
      new Date("2026-08-13T10:00:00.000Z"),
    );

    expect(reopened?.status).toBe("OPEN");
    expect(reopened?.statusReason).toBeUndefined();
    expect(reopened?.statusChangedAt).toBe("2026-08-13T10:00:00.000Z");
  });

  it("rejects a transition the lifecycle does not allow", async () => {
    await service.setFindingStatus("fnd_1", "FALSE_POSITIVE", "Test fixture.", NOW);

    await expect(
      service.setFindingStatus("fnd_1", "SUPPRESSED", "Because.", NOW),
    ).rejects.toBeInstanceOf(InvalidStatusTransitionError);
  });

  it("leaves a same-status call untouched and ignores its reason", async () => {
    await service.setFindingStatus("fnd_1", "ACCEPTED_RISK", "Original.", NOW);

    const again = await service.setFindingStatus(
      "fnd_1",
      "ACCEPTED_RISK",
      "Rewritten without a transition.",
      new Date("2026-08-20T10:00:00.000Z"),
    );

    expect(again?.statusReason).toBe("Original.");
    expect(again?.statusChangedAt).toBe("2026-08-12T10:00:00.000Z");
  });

  it("returns null for an unknown id", async () => {
    expect(
      await service.setFindingStatus("fnd_missing", "ACCEPTED_RISK", "x", NOW),
    ).toBeNull();
  });
});
```

`SecurityService`'s constructor is `(findings, scanRuns = new InMemoryScanRunRepository(), supportedScanners = [])`, so the one-argument construction above is correct.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npx vitest run tests/services/finding-status.test.ts
```

Expected: FAIL — `InvalidStatusReasonError` is not exported, and `setFindingStatus` takes three parameters.

- [ ] **Step 3: Add the error classes**

In `src/domain/security/errors.ts`, before `isSecurityDomainError`:

```ts
/**
 * A manual status change the lifecycle does not allow.
 *
 * 409 rather than 400: the request is well-formed, it conflicts with the
 * finding's current state. The message names the two statuses and nothing else
 * — it never carries finding content.
 */
export class InvalidStatusTransitionError extends SecurityDomainError {
  readonly code = "INVALID_STATUS_TRANSITION";
  readonly httpStatus = 409;

  constructor(from: string, to: string) {
    super(`Cannot transition a finding from ${from} to ${to}.`);
  }
}

/** A missing, blank or over-long justification. Never quotes what was sent. */
export class InvalidStatusReasonError extends SecurityDomainError {
  readonly code = "INVALID_STATUS_REASON";
  readonly httpStatus = 400;
}
```

- [ ] **Step 4: Add the schema**

In `src/lib/security/validation/schemas.ts`, import the limit and export the schema next to the other field schemas:

```ts
import { MAX_STATUS_REASON_LENGTH } from "@/lib/security/status-change";
```

```ts
/**
 * Justification for a manual status change.
 *
 * Trimmed before length is measured, so 500 spaces is not a valid reason. The
 * text is free-form: it is written by a person about their own system, and it
 * is rendered as text, never as HTML.
 */
export const statusReasonSchema = z
  .string()
  .trim()
  .min(1)
  .max(MAX_STATUS_REASON_LENGTH);
```

- [ ] **Step 5: Rewrite setFindingStatus**

Replace the method at `src/lib/security/services/security-service.ts:294-316`:

```ts
  /**
   * Apply a human decision to a finding (accept risk, mark false positive, …).
   *
   * Invalid transitions are rejected rather than silently applied, and the three
   * human-decided statuses require a justification: an accepted risk with no
   * recorded reason is not auditable, which is the whole point of the status.
   */
  async setFindingStatus(
    id: string,
    status: FindingStatus,
    reason: string | undefined,
    now: Date = new Date(),
  ): Promise<SecurityFinding | null> {
    const finding = await this.findings.findById(id);
    if (!finding) return null;
    // A no-op transition must not become a way to rewrite an existing
    // justification without a real state change.
    if (finding.status === status) return finding;
    if (!canTransition(finding.status, status)) {
      throw new InvalidStatusTransitionError(finding.status, status);
    }

    let statusReason: string | undefined;
    if (isHumanDecided(status)) {
      const parsed = statusReasonSchema.safeParse(reason ?? "");
      if (!parsed.success) {
        throw new InvalidStatusReasonError(
          `A justification of 1 to ${MAX_STATUS_REASON_LENGTH} characters is required to set a finding to ${status}.`,
        );
      }
      statusReason = parsed.data;
    } else if (reason !== undefined) {
      const parsed = statusReasonSchema.safeParse(reason);
      if (!parsed.success) {
        throw new InvalidStatusReasonError(
          `A justification may be at most ${MAX_STATUS_REASON_LENGTH} characters.`,
        );
      }
      statusReason = parsed.data;
    }

    return this.findings.update(id, {
      status,
      resolvedAt: status === "RESOLVED" ? now.toISOString() : undefined,
      // Reopening without a reason clears the old one: a justification written
      // for a status the finding no longer holds reads as a current decision.
      statusReason,
      statusChangedAt: now.toISOString(),
    });
  }
```

Add the imports at the top of the file:

```ts
import {
  InvalidStatusReasonError,
  InvalidStatusTransitionError,
} from "@/domain/security/errors";
import { canTransition, isHumanDecided } from "../lifecycle";
import { statusReasonSchema } from "../validation/schemas";
import { MAX_STATUS_REASON_LENGTH } from "../status-change";
```

`canTransition` is already imported at line 20 — extend that import rather than duplicating it.

- [ ] **Step 6: Fix the existing call site**

`tests/repository/postgres-ingestion.test.ts:137` currently calls the method with two arguments. Change it to:

```ts
      await security.setFindingStatus(
        target.id,
        "ACCEPTED_RISK",
        "Accepted for the duration of the migration.",
      );
```

- [ ] **Step 7: Run the tests to verify they pass**

```bash
npx vitest run tests/services/finding-status.test.ts tests/repository/postgres-ingestion.test.ts
```

Expected: PASS. The Postgres file skips without `TEST_DATABASE_URL`; export it so it actually runs.

- [ ] **Step 8: Commit**

```bash
git add src/domain/security/errors.ts src/lib/security/validation/schemas.ts src/lib/security/services/security-service.ts tests/services/finding-status.test.ts tests/repository/postgres-ingestion.test.ts
git commit -m "feat: require a justification for a manual status change

ACCEPTED_RISK, FALSE_POSITIVE and SUPPRESSED now need a reason, trimmed
and bounded at 500 characters; reopening without one clears the old
justification rather than leaving it to read as current. A disallowed
transition raises a 409 domain error instead of a bare Error, which
errorToResponse was correctly flattening to an opaque 500.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 4: Migration and the PostgreSQL driver

**Files:**
- Create: `db/migrations/002_finding_status_reason.sql`
- Modify: `src/lib/security/repository/postgres-security-finding-repository.ts` (lines 41-52, 54-88, 98-134, 136-172, 174-179, 355-388)
- Test: `tests/repository/repository-contract.ts` (lines 97-135 and after line 337)

**Interfaces:**
- Consumes: the two domain fields from Task 1.
- Produces: both fields persisted by every driver, reading back `undefined` when unset.

- [ ] **Step 1: Write the failing contract assertions**

In `tests/repository/repository-contract.ts`, extend the `rich` object in "round-trips every field of a finding" (after `metadata`):

```ts
        statusReason: "Accepted while the vendor patch is in flight.",
        statusChangedAt: "2026-08-08T11:30:00.000Z",
```

Extend "omits absent optional fields rather than returning null" with:

```ts
      expect(stored?.statusReason).toBeUndefined();
      expect(stored?.statusChangedAt).toBeUndefined();
```

And add a new test after "updates by id and returns the merged finding":

```ts
    it("round-trips a justification through update, and clears it", async () => {
      const target = await repository.findByFingerprint("a");

      const accepted = await repository.update(target!.id, {
        status: "ACCEPTED_RISK",
        statusReason: "Compensating control documented in RISK-88.",
        statusChangedAt: "2026-08-11T08:00:00.000Z",
      });
      expect(accepted?.statusReason).toBe(
        "Compensating control documented in RISK-88.",
      );
      expect(accepted?.statusChangedAt).toBe("2026-08-11T08:00:00.000Z");

      const reloaded = await repository.findByFingerprint("a");
      expect(reloaded?.statusReason).toBe(
        "Compensating control documented in RISK-88.",
      );
      expect(reloaded?.statusChangedAt).toBe("2026-08-11T08:00:00.000Z");

      const reopened = await repository.update(target!.id, {
        status: "OPEN",
        statusReason: undefined,
        statusChangedAt: "2026-08-12T08:00:00.000Z",
      });
      // Cleared, not stored as an empty string — the same NULL-versus-empty
      // distinction the rest of this suite guards.
      expect(reopened?.statusReason).toBeUndefined();
      expect((await repository.findByFingerprint("a"))?.statusReason).toBeUndefined();
    });
```

- [ ] **Step 2: Run the contract suite to verify it fails**

```bash
npx vitest run tests/repository/
```

Expected: the in-memory contract run PASSES all three (it stores whole objects). The Postgres run FAILS — the columns do not exist, so the values never survive a round trip. That asymmetry is exactly what the shared contract exists to expose.

- [ ] **Step 3: Write the migration**

Create `db/migrations/002_finding_status_reason.sql`:

```sql
-- Justification for a manual status change.
--
-- ACCEPTED_RISK, FALSE_POSITIVE and SUPPRESSED are decisions a person makes
-- about a real vulnerability. Storing the status without the reasoning leaves
-- no way to review the decision later.
--
-- Both columns are nullable: every finding that predates this migration has no
-- human decision attached, and a scanner-driven status never sets them.
--
-- No `changed_by` column. The application has no user authentication, so any
-- attribution stored here would be fabricated.

ALTER TABLE security_findings
  ADD COLUMN IF NOT EXISTS status_reason     TEXT,
  ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ;
```

No index: neither column is filtered or sorted on.

- [ ] **Step 4: Update the PostgreSQL repository**

Six edits in `src/lib/security/repository/postgres-security-finding-repository.ts`. All six are required; missing one produces a silent data-loss bug rather than a compile error.

1. `COLUMNS` (line 41) — extend the `status` line:

```ts
  status, first_detected_at, last_detected_at, resolved_at,
  status_reason, status_changed_at,
  remediation, source_url, metadata
`;
```

2. `COLUMN_COUNT` (line 52): `33` becomes `35`.

3. `FindingRow` (line 84, after `resolved_at`):

```ts
  status_reason: string | null;
  status_changed_at: Date | null;
```

4. `toFinding` (line 129, after `resolvedAt`):

```ts
    statusReason: undef(row.status_reason),
    statusChangedAt: iso(row.status_changed_at),
```

5. `toParams` (line 167, after `finding.resolvedAt ?? null`) — **order must match `COLUMNS` exactly**:

```ts
    finding.statusReason ?? null,
    finding.statusChangedAt ?? null,
```

6. The `ON CONFLICT DO UPDATE SET` list (line 385, after `resolved_at`):

```sql
             resolved_at = EXCLUDED.resolved_at,
             status_reason = EXCLUDED.status_reason,
             status_changed_at = EXCLUDED.status_changed_at,
```

Also update the comment at line 175-178, which cites the old column count:

```ts
/**
 * Postgres caps a statement at 65535 bound parameters. At 35 columns per row
 * that is ~1872 rows; chunk well below it so a large Trivy image report cannot
 * fail on batch size alone.
 */
```

- [ ] **Step 5: Teach the test harness about the new migration**

`tests/helpers/postgres.ts:19-30` hardcodes `001_init.sql`, so a new migration is invisible to every Postgres test until this is fixed. Read the directory instead, so migration `003` never needs this step again:

```ts
const MIGRATION_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "db",
  "migrations",
);

/**
 * Every migration, in filename order — the same order `npm run db:migrate`
 * applies them. Reading the directory rather than naming one file means a new
 * migration reaches the test schemas without editing this helper.
 */
export function migrationSql(): string {
  return readdirSync(MIGRATION_DIR)
    .filter((name) => name.endsWith(".sql"))
    .sort()
    .map((name) => readFileSync(path.join(MIGRATION_DIR, name), "utf8"))
    .join("\n");
}
```

Add `readdirSync` to the existing `node:fs` import. Confirm `scripts/migrate.mjs` already orders by filename — `grep -n "sort" scripts/migrate.mjs` — so the two paths agree.

- [ ] **Step 6: Run the contract suite**

```bash
export TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test
npx vitest run tests/repository/
```

Expected: PASS for both the in-memory and the PostgreSQL contract runs.

- [ ] **Step 7: Commit**

```bash
git add db/migrations/002_finding_status_reason.sql src/lib/security/repository/postgres-security-finding-repository.ts tests/repository/repository-contract.ts tests/helpers/postgres.ts
git commit -m "feat: persist the status justification in both drivers

Migration 002 adds two nullable columns. The in-memory store needed no
change; the contract suite is what proves the two drivers still answer
identically, including a cleared reason reading back as undefined rather
than an empty string.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 5: The Server Action

**Files:**
- Create: `src/app/dashboard/security/actions.ts`
- Test: `tests/actions/finding-status-action.test.ts` (create)

**Interfaces:**
- Consumes: `SetStatusResult`, `selectableTransitions` (Task 2); `SecurityService.setFindingStatus` (Task 3); `getSecurityService` from `src/lib/security/container.ts`.
- Produces: `setFindingStatusAction: SetFindingStatusAction`.

- [ ] **Step 1: Write the failing tests**

Create `tests/actions/finding-status-action.test.ts`:

```ts
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  InvalidStatusReasonError,
  InvalidStatusTransitionError,
} from "@/domain/security/errors";

const setFindingStatus = vi.fn();

vi.mock("@/lib/security/container", () => ({
  getSecurityService: async () => ({ setFindingStatus }),
}));

const { setFindingStatusAction } = await import(
  "@/app/dashboard/security/actions"
);

beforeEach(() => {
  setFindingStatus.mockReset();
});

describe("setFindingStatusAction", () => {
  it("returns the updated finding on success", async () => {
    setFindingStatus.mockResolvedValue({ id: "fnd_1", status: "ACCEPTED_RISK" });

    const result = await setFindingStatusAction("fnd_1", "ACCEPTED_RISK", "Why.");

    expect(result).toEqual({
      ok: true,
      finding: { id: "fnd_1", status: "ACCEPTED_RISK" },
    });
  });

  it("refuses RESOLVED before the service is consulted", async () => {
    const result = await setFindingStatusAction("fnd_1", "RESOLVED", "Why.");

    expect(result).toEqual({
      ok: false,
      code: "INVALID_STATUS_TRANSITION",
      message: expect.any(String),
    });
    expect(setFindingStatus).not.toHaveBeenCalled();
  });

  it("rejects a status that is not a finding status at all", async () => {
    const result = await setFindingStatusAction(
      "fnd_1",
      "DROP TABLE" as never,
      "Why.",
    );

    expect(result.ok).toBe(false);
    expect(setFindingStatus).not.toHaveBeenCalled();
  });

  it("reports a missing finding as NOT_FOUND", async () => {
    setFindingStatus.mockResolvedValue(null);

    const result = await setFindingStatusAction("fnd_missing", "SUPPRESSED", "Why.");

    expect(result).toEqual({
      ok: false,
      code: "NOT_FOUND",
      message: expect.any(String),
    });
  });

  it("passes a domain error's code and message through", async () => {
    setFindingStatus.mockRejectedValue(
      new InvalidStatusTransitionError("FALSE_POSITIVE", "SUPPRESSED"),
    );

    const result = await setFindingStatusAction("fnd_1", "SUPPRESSED", "Why.");

    expect(result).toMatchObject({
      ok: false,
      code: "INVALID_STATUS_TRANSITION",
    });
  });

  it("surfaces a reason error as its own code", async () => {
    setFindingStatus.mockRejectedValue(
      new InvalidStatusReasonError("A justification is required."),
    );

    const result = await setFindingStatusAction("fnd_1", "ACCEPTED_RISK", "");

    expect(result).toMatchObject({ ok: false, code: "INVALID_STATUS_REASON" });
  });

  it("never leaks an unexpected error's message", async () => {
    setFindingStatus.mockRejectedValue(
      new Error("connect ECONNREFUSED 10.0.0.4:5432 while querying findings"),
    );

    const result = await setFindingStatusAction("fnd_1", "ACCEPTED_RISK", "Why.");

    expect(result).toEqual({
      ok: false,
      code: "INTERNAL_ERROR",
      message: "The status change could not be applied.",
    });
    if (!result.ok) {
      expect(result.message).not.toContain("ECONNREFUSED");
      expect(result.message).not.toContain("10.0.0.4");
    }
  });
});
```

The last test is the one that matters: a database error message can carry an internal hostname, and this is the boundary that must not pass it on.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npx vitest run tests/actions/finding-status-action.test.ts
```

Expected: FAIL — the module does not exist.

- [ ] **Step 3: Write the action**

Create `src/app/dashboard/security/actions.ts`:

```ts
"use server";

import { isFindingStatus, type FindingStatus } from "@/domain/security/enums";
import { isSecurityDomainError } from "@/domain/security/errors";
import { getSecurityService } from "@/lib/security/container";
import type { SetStatusResult } from "@/lib/security/status-change";

/**
 * Apply a human decision to a finding.
 *
 * This is a Server Action rather than a REST route on purpose. The application
 * has no user authentication, and the only credential it owns —
 * SECURITY_INGEST_TOKEN — belongs to CI and cannot be shipped to a browser. A
 * public endpoint that flips a CRITICAL finding to FALSE_POSITIVE is a direct
 * way to hide a real vulnerability, so no such endpoint exists. The honest
 * consequence is documented in the README: whoever can reach the dashboard can
 * change a finding's status.
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
    const service = await getSecurityService();
    const finding = await service.setFindingStatus(id, status, reason);

    if (!finding) {
      return { ok: false, code: "NOT_FOUND", message: "Finding not found." };
    }

    return { ok: true, finding };
  } catch (error) {
    if (isSecurityDomainError(error)) {
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

The explicit `RESOLVED` check is deliberate rather than a call to `selectableTransitions`: it yields a specific, useful message instead of a generic rejection, and the action does not need the finding's current status to make that call.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npx vitest run tests/actions/finding-status-action.test.ts
```

Expected: PASS, all seven.

- [ ] **Step 5: Commit**

```bash
git add src/app/dashboard/security/actions.ts tests/actions/finding-status-action.test.ts
git commit -m "feat: add the status-change Server Action

No public REST route: the app has no user auth and the ingest token
belongs to CI, so an endpoint that can flip a CRITICAL finding to
FALSE_POSITIVE is not created. Failures return as values; only domain
errors, which are safe by construction, pass their message to the browser.
Manual RESOLVED is refused server-side, not just hidden in the select.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 6: Decision section in the detail drawer

**Files:**
- Modify: `src/components/security/finding-details.tsx`
- Test: `tests/components/finding-details.test.tsx` (create)

**Interfaces:**
- Consumes: `selectableTransitions`, `MAX_STATUS_REASON_LENGTH`, `SetFindingStatusAction` (Task 2).
- Produces: `FindingDetails` gains two props —
  - `onApplyStatus?: SetFindingStatusAction`
  - `onStatusChanged?: (finding: SecurityFinding) => void`

  Both optional: the drawer still renders read-only when they are absent, which keeps every existing call site compiling.

- [ ] **Step 1: Write the failing tests**

Create `tests/components/finding-details.test.tsx`:

```tsx
// @vitest-environment jsdom
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { SecurityFinding } from "@/domain/security/finding";
import { FindingDetails } from "@/components/security/finding-details";

function finding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: "fnd_1",
    fingerprint: "fp1",
    scanner: "SEMGREP",
    category: "SAST",
    severity: "CRITICAL",
    title: "SQL injection in the orders endpoint",
    repositoryName: "payment-service",
    status: "OPEN",
    firstDetectedAt: "2026-07-14T09:12:33.000Z",
    lastDetectedAt: "2026-08-10T09:12:33.000Z",
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("FindingDetails decision section", () => {
  it("offers the human decisions and never manual RESOLVED", () => {
    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={vi.fn()}
        onStatusChanged={vi.fn()}
      />,
    );

    const select = screen.getByLabelText(/change status to/i);
    const options = Array.from(
      select.querySelectorAll("option"),
    ).map((option) => option.textContent);

    expect(options).toEqual(
      expect.arrayContaining(["Accepted risk", "False positive", "Suppressed"]),
    );
    expect(options).not.toContain("Resolved");
  });

  it("shows an existing justification", () => {
    render(
      <FindingDetails
        finding={finding({
          status: "ACCEPTED_RISK",
          statusReason: "Compensating control documented in RISK-88.",
          statusChangedAt: "2026-08-11T08:00:00.000Z",
        })}
        onClose={() => {}}
      />,
    );

    expect(
      screen.getByText("Compensating control documented in RISK-88."),
    ).toBeTruthy();
  });

  it("sends the chosen status and reason, then reports the updated finding", async () => {
    const user = userEvent.setup();
    const updated = finding({ status: "ACCEPTED_RISK", statusReason: "WAF rule." });
    const onApplyStatus = vi.fn().mockResolvedValue({ ok: true, finding: updated });
    const onStatusChanged = vi.fn();

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={onApplyStatus}
        onStatusChanged={onStatusChanged}
      />,
    );

    await user.selectOptions(
      screen.getByLabelText(/change status to/i),
      "ACCEPTED_RISK",
    );
    await user.type(screen.getByLabelText(/reason/i), "WAF rule.");
    await user.click(screen.getByRole("button", { name: /apply/i }));

    await waitFor(() =>
      expect(onApplyStatus).toHaveBeenCalledWith("fnd_1", "ACCEPTED_RISK", "WAF rule."),
    );
    expect(onStatusChanged).toHaveBeenCalledWith(updated);
  });

  it("renders a failure inline and keeps the typed reason", async () => {
    const user = userEvent.setup();
    const onApplyStatus = vi.fn().mockResolvedValue({
      ok: false,
      code: "INVALID_STATUS_REASON",
      message: "A justification is required.",
    });
    const onStatusChanged = vi.fn();

    render(
      <FindingDetails
        finding={finding()}
        onClose={() => {}}
        onApplyStatus={onApplyStatus}
        onStatusChanged={onStatusChanged}
      />,
    );

    await user.selectOptions(
      screen.getByLabelText(/change status to/i),
      "SUPPRESSED",
    );
    await user.type(screen.getByLabelText(/reason/i), "Noisy rule.");
    await user.click(screen.getByRole("button", { name: /apply/i }));

    await waitFor(() =>
      expect(screen.getByText("A justification is required.")).toBeTruthy(),
    );
    expect(onStatusChanged).not.toHaveBeenCalled();
    expect(screen.getByLabelText(/reason/i)).toHaveValue("Noisy rule.");
  });

  it("hides the form entirely when no action is supplied", () => {
    render(<FindingDetails finding={finding()} onClose={() => {}} />);

    expect(screen.queryByLabelText(/change status to/i)).toBeNull();
  });
});
```

`tests/setup.ts` already imports `@testing-library/jest-dom/vitest` and calls `cleanup()` after each test, so `toHaveValue` works and no per-file teardown is needed.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npx vitest run tests/components/finding-details.test.tsx
```

Expected: FAIL — no select labelled "Change status to".

- [ ] **Step 3: Add the props and the decision section**

In `src/components/security/finding-details.tsx`, extend the imports:

```tsx
import { useEffect, useRef, useState } from "react";

import {
  categoryLabel,
  scannerLabel,
  statusLabel,
  type FindingStatus,
} from "@/domain/security/enums";
import {
  MAX_STATUS_REASON_LENGTH,
  selectableTransitions,
  type SetFindingStatusAction,
} from "@/lib/security/status-change";
```

Change the signature:

```tsx
export function FindingDetails({
  finding,
  onClose,
  onApplyStatus,
  onStatusChanged,
}: {
  finding: SecurityFinding;
  onClose: () => void;
  /** Absent in read-only contexts; the decision form is then not rendered. */
  onApplyStatus?: SetFindingStatusAction;
  onStatusChanged?: (finding: SecurityFinding) => void;
}) {
```

Add the section immediately after the existing `Lifecycle` section and before `Remediation`:

```tsx
          {(finding.statusReason || onApplyStatus) && (
            <Section title="Decision">
              {finding.statusReason && (
                <div className="border-line bg-surface-raised mb-4 rounded border px-3 py-2.5">
                  <p className="text-ink-muted text-sm leading-relaxed break-words whitespace-pre-wrap">
                    {finding.statusReason}
                  </p>
                  {finding.statusChangedAt && (
                    <p className="text-ink-faint mt-1.5 font-mono text-[10px]">
                      {statusLabel(finding.status)} ·{" "}
                      {formatDateTime(finding.statusChangedAt)}
                    </p>
                  )}
                </div>
              )}

              {onApplyStatus && (
                <DecisionForm
                  finding={finding}
                  onApplyStatus={onApplyStatus}
                  onStatusChanged={onStatusChanged}
                />
              )}
            </Section>
          )}
```

Add the form component at the bottom of the file, beside the other local components:

```tsx
/**
 * Manual status change.
 *
 * The option list comes from `selectableTransitions`, which withholds manual
 * RESOLVED. That is UI policy, and the Server Action enforces it again — this
 * select is not a security boundary.
 *
 * `statusReason` is free text a person wrote. It is rendered as JSX text like
 * every other string in this drawer; there is no `dangerouslySetInnerHTML`
 * anywhere in this codebase.
 */
function DecisionForm({
  finding,
  onApplyStatus,
  onStatusChanged,
}: {
  finding: SecurityFinding;
  onApplyStatus: SetFindingStatusAction;
  onStatusChanged?: (finding: SecurityFinding) => void;
}) {
  const targets = selectableTransitions(finding.status);
  const [target, setTarget] = useState<FindingStatus | "">("");
  const [reason, setReason] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | undefined>();

  // Defensive: every current status yields at least one target today. This
  // guards a future edit to ALLOWED_MANUAL_TRANSITIONS.
  if (targets.length === 0) return null;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!target || pending) return;

    setPending(true);
    setError(undefined);

    const result = await onApplyStatus(
      finding.id,
      target,
      reason.trim() === "" ? undefined : reason,
    );

    setPending(false);

    if (!result.ok) {
      setError(result.message);
      return;
    }

    setReason("");
    setTarget("");
    onStatusChanged?.(result.finding);
  };

  return (
    <form onSubmit={submit} className="space-y-2.5">
      <label className="block">
        <span className="text-ink-faint mb-1 block font-mono text-[10px] tracking-[0.14em] uppercase">
          Change status to
        </span>
        <select
          value={target}
          disabled={pending}
          onChange={(event) => setTarget(event.target.value as FindingStatus | "")}
          className="border-line bg-surface-raised text-ink focus:border-accent/50 w-full rounded border px-2 py-1.5 font-mono text-[11px] outline-none disabled:opacity-50"
        >
          <option value="">Select a status…</option>
          {targets.map((status) => (
            <option key={status} value={status}>
              {statusLabel(status)}
            </option>
          ))}
        </select>
      </label>

      <label className="block">
        <span className="text-ink-faint mb-1 block font-mono text-[10px] tracking-[0.14em] uppercase">
          Reason
        </span>
        <textarea
          value={reason}
          rows={3}
          maxLength={MAX_STATUS_REASON_LENGTH}
          disabled={pending}
          onChange={(event) => setReason(event.target.value)}
          placeholder="Why is this the right call? Required unless reopening."
          className="border-line bg-surface-raised text-ink placeholder:text-ink-faint focus:border-accent/50 w-full resize-y rounded border px-2 py-1.5 text-sm outline-none disabled:opacity-50"
        />
      </label>

      {error && (
        <p role="alert" className="text-fail text-xs">
          {error}
        </p>
      )}

      <button
        type="submit"
        disabled={pending || target === ""}
        className="border-line text-ink-muted hover:border-line-strong hover:text-ink rounded border px-2.5 py-1 font-mono text-[11px] transition-colors disabled:cursor-not-allowed disabled:opacity-40"
      >
        {pending ? "Applying…" : "Apply"}
      </button>
    </form>
  );
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
npx vitest run tests/components/finding-details.test.tsx
```

Expected: PASS, all five.

- [ ] **Step 5: Commit**

```bash
git add src/components/security/finding-details.tsx tests/components/finding-details.test.tsx
git commit -m "feat: add the decision form to the finding drawer

The option list withholds manual RESOLVED. A failure renders inline and
keeps the typed reason so the text is not lost. Both new props are
optional, so the drawer still renders read-only where no action is wired.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 7: Wire the action through the table and the page

**Files:**
- Modify: `src/components/security/findings-table.tsx:88-150, 453-458`
- Modify: `src/app/dashboard/security/page.tsx:120-126`
- Test: `tests/components/findings-table.test.tsx`

**Interfaces:**
- Consumes: `setFindingStatusAction` (Task 5), the two new `FindingDetails` props (Task 6).
- Produces: `FindingsTable` gains `setStatusAction?: SetFindingStatusAction`.

**Trap:** `findings-table.tsx` does not currently import from `next/navigation`. Adding `useRouter` breaks every existing test in `tests/components/findings-table.test.tsx` until the module is mocked. Do the mock in the same step as the import.

- [ ] **Step 1: Write the failing test**

Add the mock at the top of `tests/components/findings-table.test.tsx`, after the existing imports:

```tsx
const refresh = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh }),
}));
```

And add this test:

```tsx
it("refetches the current query and refreshes the page after a status change", async () => {
  const user = userEvent.setup();
  const accepted = finding({ status: "ACCEPTED_RISK", statusReason: "WAF rule." });
  const setStatusAction = vi.fn().mockResolvedValue({ ok: true, finding: accepted });

  render(
    <FindingsTable
      initialResult={initialResult}
      filterOptions={filterOptions}
      setStatusAction={setStatusAction}
    />,
  );

  await user.click(screen.getByText("Hardcoded AWS access key"));

  await user.selectOptions(
    screen.getByLabelText(/change status to/i),
    "ACCEPTED_RISK",
  );
  await user.type(screen.getByLabelText(/reason/i), "WAF rule.");
  await user.click(screen.getByRole("button", { name: /apply/i }));

  // The drawer now shows the returned finding, not an optimistic guess.
  await waitFor(() => expect(screen.getByText("WAF rule.")).toBeTruthy());

  // The current query re-runs, so a finding that left the OPEN filter goes away.
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
  expect(refresh).toHaveBeenCalled();
});
```

Add `refresh.mockReset()` to the existing `beforeEach`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npx vitest run tests/components/findings-table.test.tsx
```

Expected: FAIL — `setStatusAction` is not a prop and no select is rendered.

- [ ] **Step 3: Wire the table**

In `src/components/security/findings-table.tsx`, extend the imports:

```tsx
import { useRouter } from "next/navigation";

import type { SetFindingStatusAction } from "@/lib/security/status-change";
```

Extend the props:

```tsx
export function FindingsTable({
  initialResult,
  filterOptions,
  initialSelected,
  initialState = DEFAULT_QUERY_STATE,
  setStatusAction,
}: {
  initialResult: Page<SecurityFinding>;
  filterOptions: FilterOptions;
  initialSelected?: SecurityFinding | null;
  initialState?: FindingsQueryState;
  /**
   * Server Action, injected by the page. Passing it as a prop rather than
   * importing it keeps this component and its tests free of a server runtime.
   */
  setStatusAction?: SetFindingStatusAction;
}) {
```

Add the refresh state beside the others:

```tsx
  const [refreshToken, setRefreshToken] = useState(0);
  const router = useRouter();
```

Make the fetch effect depend on it — change the dependency array at line 150:

```tsx
  }, [queryString, refreshToken]);
```

Add the callback beside `patch`:

```tsx
  const handleStatusChanged = useCallback(
    (updated: SecurityFinding) => {
      // Show what the server actually returned, never an optimistic guess.
      setSelected(updated);
      // Re-run the current query: a newly accepted finding drops out of the
      // default OPEN filter on its own.
      setRefreshToken((token) => token + 1);
      // Re-render the server page so the "Accepted risk" and "Total open" stat
      // tiles stop showing pre-change counts. This component seeds `result`
      // from props into state, so a fresh initialResult prop is ignored and the
      // user's filters survive.
      router.refresh();
    },
    [router],
  );
```

And pass both down at line 453:

```tsx
      {selected && (
        <FindingDetails
          finding={selected}
          onClose={() => setSelected(null)}
          onApplyStatus={setStatusAction}
          onStatusChanged={handleStatusChanged}
        />
      )}
```

- [ ] **Step 4: Wire the page**

In `src/app/dashboard/security/page.tsx`, import the action and pass it:

```tsx
import { setFindingStatusAction } from "./actions";
```

```tsx
        <FindingsTable
          initialResult={firstPage}
          filterOptions={filterOptions}
          initialSelected={selectedFinding}
          setStatusAction={setFindingStatusAction}
        />
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
npx vitest run tests/components/
```

Expected: PASS — the new test and every pre-existing one in both component files.

- [ ] **Step 6: Verify it in the running app**

Restart the dev server rather than relying on a save: **the container is cached on `globalThis`** so it survives HMR, and container or seeding changes need a restart.

Start it through the preview tooling (never `npm run dev` in a shell), open `/dashboard/security`, click a finding, set it to Accepted risk with a reason, and confirm three things: the row leaves the Open filter, the "Accepted risk" stat tile increments, and reopening the drawer shows the reason.

Mock data is tuned to exactly 23 open / 3 critical / 7 high / 13 medium / 0 low — the tile should read one fewer open after an acceptance.

- [ ] **Step 7: Commit**

```bash
git add src/components/security/findings-table.tsx src/app/dashboard/security/page.tsx tests/components/findings-table.test.tsx
git commit -m "feat: wire the status change through the findings table

The action is injected from the server page rather than imported by the
client component, so component tests pass a stub instead of booting a
server runtime. A change bumps a refresh token so the current query
re-runs, and calls router.refresh() so the stat tiles above the table
stop showing pre-change counts.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Task 8: Documentation and full verification

`README.md` is the real documentation for this project and is kept current. Four sections are now wrong.

**Files:**
- Modify: `README.md` — "Security finding lifecycle" (line ~157), "Schema" (line ~426), "Testing" (line ~529), "Known limitations" (line ~573)

- [ ] **Step 1: Document the manual decision path**

In "Security finding lifecycle", add a subsection covering: which statuses a person can set from the drawer, that a justification is required for all three and stored in `statusReason` with `statusChangedAt`, that reopening without a reason clears it, that manual `RESOLVED` is deliberately not offered because it would make MTTR assertable by hand, and that no actor is recorded because there is no authentication to derive one from.

- [ ] **Step 2: Document the schema and the write path**

In "Schema", add `status_reason TEXT` and `status_changed_at TIMESTAMPTZ`, noting migration `002` and that neither is indexed because neither is filtered or sorted on.

Add a short "Changing a finding's status" note stating that the write path is a Server Action, not an API route, and why: no user authentication exists, the ingest token belongs to CI, and a public endpoint able to mark a CRITICAL finding as a false positive is a way to hide a vulnerability.

- [ ] **Step 3: Correct the limitations**

Remove:

> - Manual status changes (accept risk, false positive) exist in the service and are tested, but are not yet exposed as a UI control.

Add:

> - Anyone who can reach the dashboard can change a finding's status. There is no user authentication, so decisions are recorded with a justification but no author.

- [ ] **Step 4: Update the test counts**

Run the suite both ways and write the real numbers into "Testing", replacing "272 tests without a database; 323 with one." Also update the contract suite's assertion count if the number of `it(` blocks in `tests/repository/repository-contract.ts` changed — Task 4 adds one, so 45 becomes 46.

```bash
npx vitest run 2>&1 | tail -5
export TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/dashboard_test
npx vitest run 2>&1 | tail -5
```

- [ ] **Step 5: Run the full verification chain**

```bash
npm run lint && npm run typecheck && npm test && npm run build
```

Expected: all four clean, with `TEST_DATABASE_URL` exported so the Postgres suites run rather than skip. Do not claim the work is done on a run where they skipped.

- [ ] **Step 6: Commit**

```bash
git add README.md
git commit -m "docs: document the manual status control

Covers the decision path and its justification field, the two new
columns, and the Server Action write path. Replaces the 'not yet exposed
as a UI control' limitation with the honest one: anyone who can reach the
dashboard can change a status, and no author is recorded because there is
no authentication to derive one from.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Self-review notes

Checked against `docs/superpowers/specs/2026-08-07-manual-finding-status-design.md`:

- Every spec section maps to a task: domain → 1, errors → 3, service → 3, storage → 4, Server Action → 5, UI → 6, data flow → 7, documentation → 8.
- Two spec details were tightened during planning, both recorded above rather than left implicit:
  - The action is **injected as a prop** from the server page rather than imported by the client component. Same behaviour, and it keeps a server module out of jsdom tests.
  - `reconcileFinding`'s NEW branch must **clear** `statusReason` / `statusChangedAt`, not merely preserve them. The spec covered the merge path; the NEW path would otherwise let a scanner adapter plant a justification. Task 1 Step 1's third test covers it.
- Two pre-existing files break and are fixed in-plan: `tests/repository/postgres-ingestion.test.ts:137` calls `setFindingStatus` with the old two-argument signature (Task 3 Step 6), and `tests/helpers/postgres.ts:19-30` hardcodes `001_init.sql`, so migration `002` would be invisible to every Postgres test (Task 4 Step 5).
- Names are consistent across tasks: `statusReason`, `statusChangedAt`, `selectableTransitions`, `SetStatusResult`, `SetFindingStatusAction`, `setFindingStatusAction`, `onApplyStatus`, `onStatusChanged`, `setStatusAction`, `refreshToken`.
