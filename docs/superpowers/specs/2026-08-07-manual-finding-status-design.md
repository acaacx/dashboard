# Manual finding status control

**Date:** 2026-08-07
**Status:** approved, not yet implemented

## Problem

`SecurityService.setFindingStatus` and `canTransition` already implement human
decisions on findings — accept risk, mark false positive, suppress — and both are
covered by tests. Nothing in the UI can reach them. The README lists this under
Known limitations: "Manual status changes (accept risk, false positive) exist in
the service and are tested, but are not yet exposed as a UI control."

A second gap sits behind it: an `ACCEPTED_RISK` finding currently records no
justification. The status asserts that somebody looked at a real vulnerability
and decided to live with it, and the store keeps no trace of why.

## Scope

In scope:

- two new optional domain fields carrying the justification and its timestamp
- a Server Action that applies a status change
- a decision control in the finding detail drawer
- a `409` domain error for invalid transitions
- migration and both repository drivers
- tests at every layer

Out of scope, deliberately:

- bulk or row-level status changes
- user authentication
- attribution of a decision to a named person
- exposing manual `OPEN -> RESOLVED` in the UI

## Decisions taken

### Authentication: Server Action, no new credential

The application has no user authentication. The only credential is
`SECURITY_INGEST_TOKEN`, which belongs to CI and cannot be shipped to a browser.
A public write endpoint that flips a `CRITICAL` finding to `FALSE_POSITIVE` is a
direct way to hide a real vulnerability, so it is not created.

The mutation runs as a Next.js Server Action instead of a REST route. No
credential reaches the browser, and no new secret exists to leak. The honest
consequence — whoever can reach the dashboard can change a finding's status —
is documented in the README next to the existing "authenticated but not
rate-limited" caveat, rather than papered over with a token that the UI would
have to hold client-side anyway.

Rejected: a public `PATCH /api/security/findings/:id` behind a new
`SECURITY_ADMIN_TOKEN`. The browser UI would need that token to call it, which
defeats the token.

### Audit trail: first-class fields, no actor

`statusReason` and `statusChangedAt` become optional fields on `SecurityFinding`.

Rejected: storing the reason in the existing `metadata` JSONB. `metadata` is
scanner-owned — `reconcileFinding` merges incoming over existing, so a scanner
key could overwrite a human decision — and the drawer renders it under a
"Scanner metadata" heading. Two different trust levels do not belong in one bag.

No `changedBy` field. Without authentication there is no trustworthy identity,
and recording one would fabricate attribution.

### Placement: detail drawer only

One control, in `FindingDetails`, where the reader has already seen the
description, location and remediation. A status change is a considered decision;
a one-click action from a table row invites mistakes.

### Transitions offered: human decisions and reopen

The UI offers `ACCEPTED_RISK`, `FALSE_POSITIVE`, `SUPPRESSED`, and reopening to
`OPEN`. It does not offer manual `RESOLVED`, even though `canTransition` permits
`OPEN -> RESOLVED`.

`RESOLVED` means a scan stopped seeing the finding. Letting a person assert it by
hand makes mean-time-to-remediate a number anyone can improve without fixing
anything. The service keeps permitting the transition — the restriction is a UI
policy, and the divergence is intentional and commented at both ends.

## Design

### Domain

Added to `SecurityFinding` in `src/domain/security/finding.ts`:

```ts
/** Why a human set the current status. Absent unless a person decided. */
statusReason?: string;
/** ISO-8601 UTC instant of the last manual status change. */
statusChangedAt?: string;
```

Neither field enters the fingerprint. Invariant 5 is unchanged.

**Critical:** `reconcileFinding` in `src/lib/security/lifecycle.ts` spreads
`...incoming` over the existing finding and then restores identity and history
fields explicitly — `id`, `fingerprint`, `firstDetectedAt`, `lastDetectedAt`,
`status`, `resolvedAt`. Both new fields must join that restore list. Omitting
them means the next scan silently erases every recorded justification, which is
the same failure mode the `firstDetectedAt` rule exists to prevent. On the
`RESOLVED -> OPEN` reopen path (a scan seeing a resolved finding again) the
fields are preserved as-is: that reopen is scanner-driven, not a human decision,
so it does not invent or clear a justification.

### Errors

New in `src/domain/security/errors.ts`:

```ts
export class InvalidStatusTransitionError extends SecurityDomainError {
  readonly code = "INVALID_STATUS_TRANSITION";
  readonly httpStatus = 409;
}
```

Today an invalid transition throws a plain `Error`, which `errorToResponse`
correctly flattens to an opaque `INTERNAL_ERROR` 500 — the wrong status for a
client-correctable conflict. The message names the two statuses and nothing
else; it carries no finding content.

A second class covers the reason itself:

```ts
export class InvalidStatusReasonError extends SecurityDomainError {
  readonly code = "INVALID_STATUS_REASON";
  readonly httpStatus = 400;
}
```

It is raised for a missing or blank reason where one is required, and for a
reason exceeding the length limit. One code, two triggers — the message
distinguishes them, and neither message quotes the submitted text.

### Service

`SecurityService.setFindingStatus` gains the reason:

```ts
async setFindingStatus(
  id: string,
  status: FindingStatus,
  reason: string | undefined,
  now: Date = new Date(),
): Promise<SecurityFinding | null>
```

Behaviour:

- unknown id returns `null` (unchanged)
- a call whose target equals the current status is a no-op: the finding is
  returned untouched and any submitted reason is ignored, so this path can never
  be used to rewrite an existing justification without a real transition
- disallowed transition throws `InvalidStatusTransitionError`
- `ACCEPTED_RISK`, `FALSE_POSITIVE`, `SUPPRESSED` require a non-empty reason
- `OPEN` (reopen) takes an optional reason; when absent, `statusReason` is
  cleared, because a stale justification attached to a reopened finding reads as
  a current decision
- `statusChangedAt` is set to `now.toISOString()` on every applied change
- `resolvedAt` handling is unchanged

The reason is validated by a Zod schema next to the existing ones in
`src/lib/security/validation/schemas.ts`: trimmed, non-empty after trimming,
maximum 500 characters. Validation lives in the service so both the Server Action
and any future caller inherit it.

### Storage

`db/migrations/002_finding_status_reason.sql`, forward-only:

```sql
ALTER TABLE security_findings
  ADD COLUMN status_reason TEXT,
  ADD COLUMN status_changed_at TIMESTAMPTZ;
```

Both drivers map the columns. NULL must read back as `undefined`, never `""` or
`null` — the same class of bug the contract suite already guards for other
nullable columns. The Postgres row mapper, the insert/upsert column list and the
`update` patch builder all need the two fields; the in-memory driver stores them
directly.

### Server Action

`src/app/dashboard/security/actions.ts`, marked `"use server"`:

```ts
export type SetStatusResult =
  | { ok: true; finding: SecurityFinding }
  | { ok: false; code: string; message: string };

export async function setFindingStatusAction(
  id: string,
  status: FindingStatus,
  reason: string | undefined,
): Promise<SetStatusResult>;
```

It returns a discriminated result rather than throwing, so a failure never
surfaces a stack trace or an internal path to the browser. Mapping mirrors
`errorToResponse`: a `SecurityDomainError` yields its own code and message; any
other thrown value yields `INTERNAL_ERROR` with a fixed generic message. A
missing finding yields `{ ok: false, code: "NOT_FOUND" }`.

The action re-validates `status` against `isFindingStatus` and rejects
`RESOLVED` outright, so the UI-policy restriction is enforced server-side and not
only in the select element.

### UI

`FindingDetails` gains a `Decision` section below `Lifecycle`:

- when `statusReason` is present, it is displayed with `statusChangedAt`
- a select listing permitted targets, computed from `canTransition(finding.status, …)`
  with `RESOLVED` filtered out
- a reason textarea, required unless the target is `OPEN`
- an Apply button; the form is disabled while the action is pending
- failure renders inline and leaves the drawer open with the input intact

`statusReason` is untrusted text rendered as JSX text. No
`dangerouslySetInnerHTML` — invariant 6 is unchanged.

The drawer stays presentational apart from calling the action. It takes an
`onStatusChanged(finding: SecurityFinding) => void` prop.

Every current status yields at least one permitted target once `RESOLVED` is
filtered out, so the section always renders today. The empty-list guard is
defensive, against a future edit to `ALLOWED_MANUAL_TRANSITIONS`.

### Data flow after a change

`FindingsTable` owns the refresh:

1. drawer calls the action, receives the updated finding
2. drawer invokes `onStatusChanged(updated)`
3. table replaces `selected` with the returned finding, so the drawer's badges
   update from real data rather than an optimistic guess
4. table increments a `refreshToken` in state; `refreshToken` is a dependency of
   the existing debounced fetch effect, so the current query re-runs and a newly
   accepted finding leaves the default `OPEN` filter on its own
5. table calls `router.refresh()`, re-rendering the server page so the
   "Accepted risk" and "Total open" stat tiles stop showing pre-change counts

Step 5 does not disturb the table: `FindingsTable` seeds `result` from props into
`useState`, so a new `initialResult` prop is ignored and client filter state
survives. That is the component's existing contract — server data is the seed,
the client owns it afterwards — and this design does not change it.

## Error handling summary

| Condition | Surface | Result |
|---|---|---|
| Unknown finding id | action | `{ ok: false, code: "NOT_FOUND" }` |
| Disallowed transition | service throws, action maps | `INVALID_STATUS_TRANSITION`, 409-equivalent |
| Missing or blank reason where required | service throws, action maps | `INVALID_STATUS_REASON`, 400 |
| Reason over 500 chars | service throws, action maps | `INVALID_STATUS_REASON`, 400 |
| `RESOLVED` requested | action rejects before service | `INVALID_STATUS_TRANSITION` |
| Database failure | retry layer, then action maps | `INTERNAL_ERROR`, generic message |

## Testing

New coverage, by layer:

- **lifecycle:** `reconcileFinding` preserves `statusReason` and
  `statusChangedAt` across a subsequent scan, on both the human-decided path and
  the scanner-driven reopen path
- **service:** writes reason and timestamp; throws `InvalidStatusTransitionError`
  on a disallowed transition; rejects a missing or blank reason for each of the
  three human statuses; clears `statusReason` on reopen without a reason; leaves
  a same-status call untouched
- **repository contract:** `update` round-trips both fields through both drivers,
  and a finding never given a reason reads back `undefined` rather than `""` or
  `null`
- **action:** maps a domain error to its code, maps an unknown throw to
  `INTERNAL_ERROR` with no leaked message, rejects `RESOLVED`
- **component:** the select excludes `RESOLVED` and lists exactly the permitted
  targets for the finding's current status; a failed action renders an inline
  error and keeps the drawer open; a successful action calls `onStatusChanged`

Component tests wait for the expected query rather than reading the last fetch
call — filters are debounced 200 ms and two changes race under CPU load.

Verification before the work is called done:

```bash
npm run lint && npm run typecheck && npm test && npm run build
```

with `TEST_DATABASE_URL` set, so the Postgres suites run rather than skip.

## Documentation

README updates required, since it is the real documentation and is kept current:

- "Security finding lifecycle" gains the manual-decision path and the reason field
- "Known limitations" drops the manual-status entry and gains the honest note
  that the control is reachable by anyone who can reach the dashboard
- "Schema" gains the two columns; "Testing" gains the new counts
