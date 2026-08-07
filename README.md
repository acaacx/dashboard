# DevSecOps Dashboard

Centralised security and delivery observability. Ingests, normalizes, stores and
displays security findings from open-source scanners — Semgrep, Trivy, Checkov
and Gitleaks — behind one scanner-independent domain model.

Built with Next.js 16 (App Router), React 19, TypeScript (strict), Tailwind CSS
v4, Recharts, Zod and Vitest.

```bash
npm install
npm run dev
```

Open http://localhost:3000 — it redirects to `/dashboard`. The store is seeded
with clearly-labelled mock scan results so every page has data on first run.

| Command | What it does |
|---|---|
| `npm run dev` | Development server |
| `npm run build` | Production build |
| `npm run lint` | ESLint |
| `npm run typecheck` | `next typegen` + `tsc --noEmit` |
| `npm test` | Vitest (unit + component) |

---

## Security architecture

```
GitHub Actions
      │
      ├── Semgrep ──┐
      ├── Trivy ────┤
      ├── Checkov ──┤   SARIF / native JSON
      └── Gitleaks ─┘
                     │
                     ▼
             Scanner Adapters          ← the only layer that knows a vendor format
                     │
                     ▼
             Result Normalizer         ← severity, category, fingerprint
                     │
                     ▼
           SecurityFinding (domain)    ← scanner-independent
                     │
                     ▼
        SecurityFindingRepository      ← swappable persistence
                     │
                     ▼
         SecurityService / Ingestion   ← all metrics computed here
                     │
                     ▼
                 API layer
                     │
                     ▼
                    UI
```

The rule that shapes everything else: **React components never see scanner
output.** They receive `SecurityFinding` objects and pre-computed statistics. A
component cannot decide that something is a "secret" or "critical" — an adapter
decided that long before render.

### Layout

```
src/
  domain/security/            enums, SecurityFinding, ScanRun, errors, inventory contracts
  lib/security/
    adapters/                 semgrep, trivy, checkov, gitleaks + registry
    parsers/sarif-parser.ts   generic SARIF 2.1.0 reader
    normalization/            severity.ts, categories.ts, fingerprint.ts
    repository/               interface + in-memory implementations
    services/                 security-service.ts, scan-ingestion-service.ts
    validation/schemas.ts     Zod schemas for the HTTP boundary
    mock/                     MOCK payloads + seeder (dev only)
    lifecycle.ts              NEW / EXISTING / REOPENED / RESOLVED
    observability.ts          lightweight event seam
    container.ts              composition root
  providers/platform.ts       GitHub | Azure | Security provider seam
  app/api/security/           REST endpoints
  app/dashboard/              Overview, Security, Applications, Pipelines
  components/security/        charts, table, drawer, scanner status
tests/                        unit + component tests, fixtures/
```

---

## Supported scanners

| Scanner | Formats | Category | Notes |
|---|---|---|---|
| Semgrep | native JSON, SARIF | `SAST` | native preferred — carries CWE, impact, autofix, stable fingerprint |
| Trivy | native JSON, SARIF | `SCA`, `CONTAINER`, `IAC`, `SECRET`, `CONFIGURATION` | native strongly preferred — SARIF loses package/fixed-version data |
| Checkov | native JSON, SARIF | `IAC` | handles both the object and array envelope shapes |
| Gitleaks | native JSON, SARIF | `SECRET` | secret values are discarded, never stored |

Architecture is prepared for — but does not implement — Syft, Grype, OWASP ZAP,
CodeQL, Dependabot, GitHub Secret Scanning and Microsoft Defender for Cloud.
Each is an adapter plus a registry line; see "Adding a new scanner".

---

## Scanner normalization

### Severity

`src/lib/security/normalization/severity.ts` is the only place that knows vendor
severity vocabularies. It accepts strings (`HIGH`, `warning`, `blocker`), numbers
(CVSS) and numeric strings, and returns `UNKNOWN` rather than guessing.

Documented policies, each in one named constant so they are easy to change:

- **SARIF `error` maps to `HIGH`, not `CRITICAL`.** Promoting every SARIF error
  to critical makes the critical count meaningless.
- **Semgrep `ERROR` + `impact: HIGH` + confidence not LOW becomes `CRITICAL`.**
  Semgrep has only three severities; without this, a SQL-injection finding
  permanently outranks nothing.
- **Checkov defaults to `MEDIUM`** (`CHECKOV_DEFAULT_SEVERITY`). Open-source
  Checkov emits `severity: null`; a real severity always overrides the default.
- **Gitleaks defaults to `CRITICAL`** (`GITLEAKS_DEFAULT_SEVERITY`). A live
  credential in version control is treated as critical by policy.

### Category

Category answers "what kind of problem is this", independent of which tool found
it. Single-purpose scanners get a fixed category. Trivy resolves **per result**,
because one Trivy report legitimately contains OS package CVEs (`CONTAINER`),
application dependencies (`SCA`), IaC misconfigurations (`IAC`) and secrets
(`SECRET`) side by side.

---

## SARIF support

`parseSarif()` reads SARIF 2.1.0 and knows nothing about any specific tool.
Adapters call it for the generic 90% and override only what they alone know.

- resolves rules by `ruleId` and by `ruleIndex`, on the driver or on extensions
- prefers numeric `security-severity` over the coarse `level`
- reads `partialFingerprints` as stable identity (survives line movement)
- `suppressions` become `status: SUPPRESSED` rather than being dropped
- `kind: pass` / `notApplicable` are skipped — those are scan metadata
- capped at 50,000 results per document
- defensive throughout: a missing optional field yields an incomplete finding,
  not an exception. Only a payload that is not SARIF is rejected
  (`InvalidSarifError`).

---

## Security finding lifecycle

```
(absent) ──scan sees it──▶  NEW      stored as OPEN
OPEN     ──scan sees it──▶  EXISTING lastDetectedAt advances
OPEN     ──scan misses──▶   RESOLVED resolvedAt set
RESOLVED ──scan sees it──▶  REOPENED stored as OPEN, resolvedAt cleared

OPEN ──▶ ACCEPTED_RISK | FALSE_POSITIVE | SUPPRESSED   (human decisions)
```

Two invariants:

1. **`firstDetectedAt` is never overwritten.** It is the age of the problem and
   it feeds mean-time-to-remediate. Out-of-order scans keep the earliest value.
2. **Human decisions outrank scanners.** `ACCEPTED_RISK`, `FALSE_POSITIVE` and
   `SUPPRESSED` are never auto-reopened or auto-resolved; their
   `lastDetectedAt` still advances so "accepted and still present" is
   distinguishable from "accepted and since fixed".

Auto-resolution is **scoped**: a scan only resolves findings from the same
scanner, repository and environment. A Semgrep run says nothing about Trivy
findings. Pass `autoResolveMissing: false` for partial or path-filtered scans.

---

## Deduplication

`generateFindingFingerprint()` produces a deterministic SHA-256 identity so a
pipeline running on every push does not create duplicate findings.

**Included:** scanner, rule id (or title), repository, file, start line,
package name, CVE, resource / Azure resource id, environment. A scanner-native
stable id (SARIF `partialFingerprints`, Gitleaks `Fingerprint`, Semgrep
`extra.fingerprint`) short-circuits all positional inputs.

**Excluded, deliberately:** timestamps of any kind, severity (scanners re-rate
findings), status, description (vendors reword rule text), commit SHA, branch,
and installed package version (the state of a dependency finding, not its
identity).

**Known trade-off:** `startLine` is part of the identity, so unrelated edits that
shift line numbers resolve the old finding and open a new one. Scanner-native
stable ids avoid this and are preferred wherever a scanner provides one.

Duplicates are collapsed twice: within a single payload (Trivy lists a CVE once
per layer) and against the store by fingerprint.

---

## Scan ingestion

```
POST /api/security/scans
Authorization: Bearer $SECURITY_INGEST_TOKEN
Content-Type: application/json

{
  "scanner": "TRIVY",
  "format": "json",
  "repositoryId": "repo_order_service",
  "repositoryName": "order-service",
  "branch": "main",
  "commitSha": "71b3e5d…",
  "workflowRunId": "1234567890",
  "workflowRunUrl": "https://github.com/org/repo/actions/runs/1234567890",
  "applicationId": "app_commerce",
  "environment": "production",
  "scannedAt": "2026-08-10T11:52:00Z",
  "results": { "…": "raw scanner output" }
}
```

Response `201`:

```json
{
  "scanRunId": "run_…",
  "scanner": "TRIVY",
  "status": "COMPLETED",
  "summary": {
    "received": 12, "duplicatesInPayload": 2,
    "created": 3, "updated": 7, "reopened": 0, "resolved": 1
  }
}
```

### Authentication

The endpoint requires `Authorization: Bearer <token>` matching
`SECURITY_INGEST_TOKEN`, compared in constant time.

**It fails closed:** if `SECURITY_INGEST_TOKEN` is unset, the endpoint returns
`503` in production. It is permitted without a token only when
`NODE_ENV !== "production"`, for local development.

Upgrade path for a real deployment, in rough order of value: per-repository
tokens so one leaked CI secret cannot write for every repo; GitHub OIDC so
Actions exchanges a short-lived token instead of holding a static one; and a
network boundary (mTLS or a private ingress) so the endpoint is not reachable
from the public internet at all.

### Input safety

- body capped at 8 MB, checked before parsing (Content-Length *and* actual size)
- envelope validated with Zod; repository, branch and commit are pattern-constrained
- **no field accepts a filesystem path or a URL to fetch** — output travels in the body
- the scanner payload itself is intentionally *not* schema-validated; it reaches
  adapters as `unknown` and is parsed defensively, because scanners add fields
  between releases and a strict schema would reject valid reports
- a malformed payload produces a `FAILED` ScanRun and a safe error, never a crash
- errors and telemetry never include payload fragments or secrets

### XSS posture

All scanner-supplied text — title, description, remediation, metadata — is
rendered as text through JSX, which escapes it. There is **no
`dangerouslySetInnerHTML` anywhere in this codebase**, and `sourceUrl` is
scheme-checked (`http:`/`https:` only) before becoming a link, so a
`javascript:` URL in a rule definition cannot execute.

---

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/security/findings` | Paginated, filtered findings |
| `GET /api/security/findings/:id` | One finding |
| `GET /api/security/statistics` | Aggregates + trend + scanner health |
| `GET /api/security/scans` | Scan runs + scanner health |
| `POST /api/security/scans` | Ingest scanner output (authenticated) |

Filters are comma-separated and applied **server-side**:

```
GET /api/security/findings?severity=CRITICAL,HIGH&scanner=GITLEAKS&status=OPEN
GET /api/security/findings?repository=payment-service&environment=production
GET /api/security/findings?search=CVE-2026-3456&page=2&pageSize=25
GET /api/security/statistics?timeframe=7d&trendDays=30
```

Supported: `severity`, `scanner`, `category`, `status`, `repository`,
`environment`, `search`, `timeframe` (`24h` / `7d` / `30d` / `all`), `page`,
`pageSize`, `sortBy`, `sortDirection`. Search covers title, CVE, CWE,
repository, file, resource, rule id and package name.

---

## GitHub Actions integration

A complete example lives in
[`docs/examples/github-actions-security-scan.yml`](docs/examples/github-actions-security-scan.yml)
(kept under `docs/` so this repository never executes it). It runs all four
scanners, uploads each report as a normal artifact, and posts the raw output to
the dashboard:

```yaml
- name: Send Semgrep results to the dashboard
  if: always()
  run: |
    jq -n \
      --arg scanner "SEMGREP" \
      --arg repositoryName "${{ github.repository }}" \
      --arg branch "${{ github.ref_name }}" \
      --arg commitSha "${{ github.sha }}" \
      --arg workflowRunId "${{ github.run_id }}" \
      --slurpfile results semgrep.json \
      '{scanner: $scanner, repositoryName: $repositoryName, branch: $branch,
        commitSha: $commitSha, workflowRunId: $workflowRunId,
        results: $results[0]}' > payload.json

    curl --fail-with-body -sS -X POST "$DASHBOARD_URL/api/security/scans" \
      -H "Authorization: Bearer $DASHBOARD_TOKEN" \
      -H "Content-Type: application/json" \
      --data @payload.json
  env:
    DASHBOARD_URL: ${{ vars.DEVSECOPS_DASHBOARD_URL }}
    DASHBOARD_TOKEN: ${{ secrets.DEVSECOPS_DASHBOARD_TOKEN }}
```

`if: always()` matters: scanners exit non-zero when they find something, and a
finding is exactly when you most want the dashboard updated.

---

## Inventory correlation

Repository and Azure inventory are owned elsewhere. **No inventory scanner is
implemented here** — `src/domain/security/inventory.ts` contains contracts only:

```
Finding → Repository → Application → Environment → Azure Resource
```

`NoopAssetCorrelationService` is wired in today; it enriches nothing.
`InventoryAssetCorrelationService` is the reference implementation for when an
`InventoryProvider` exists. Connecting it is a one-line change in
`src/lib/security/container.ts`.

Correlation is **strictly ID-driven**. `getRepositoryByName` is documented as
exact-match only: silently attributing a critical finding to the wrong
application is worse than no correlation at all. Values already asserted by CI
always win over inventory-derived ones.

Not every finding reaches the end of the chain — a Semgrep finding in a library
repo may never map to an Azure resource, and that is a valid final state.

---

## Adding a new scanner

No UI changes required. That is the acceptance criterion.

1. Add the scanner to `SCANNER_TYPES` in `src/domain/security/enums.ts`
2. Create `src/lib/security/adapters/<name>-adapter.ts` implementing
   `ScannerAdapter` (`canHandle` + `parse`)
3. Map severity — add vendor tokens to `normalization/severity.ts` if needed
4. Map category — a fixed category, or per-result if the tool is multi-purpose
5. Add fixtures under `tests/fixtures/<name>/`
6. Add tests mirroring `tests/adapters/*.test.ts`
7. Register it in `createDefaultAdapterRegistry()`

The UI derives scanner lists from the data (`statistics.byScanner`), and labels
fall back to a title-cased enum value, so a new scanner appears in charts,
filters and the table automatically.

---

## Storage, and future PostgreSQL

Today: `InMemorySecurityFindingRepository` and `InMemoryScanRunRepository`.
Deliberately — there is no database to run, no migrations to maintain, and the
in-memory implementation exercises the full `SecurityFindingRepository`
interface, so a SQL implementation has a contract to satisfy rather than a shape
to invent.

**Stated limitations:** state is per-process and lost on restart, and in a
multi-instance deployment each instance would hold a different set.

Migration path — implement `SecurityFindingRepository` against these tables and
swap it in `container.ts`:

| Table | Key columns |
|---|---|
| `security_findings` | `fingerprint` UNIQUE, `id`, scanner, category, severity, status, `first_detected_at`, `last_detected_at`, `resolved_at`, repository/application/environment ids, `metadata jsonb` |
| `scan_runs` | `id`, scanner, repository, branch, commit, status, timings, per-severity counts |
| `scanner_sources` | registered scanner + credentials/config per repository |
| `repositories`, `applications`, `environments` | inventory projections, when inventory is connected |

`fingerprint` is the natural key — a `UNIQUE` constraint plus
`INSERT … ON CONFLICT (fingerprint) DO UPDATE` gives the same dedup semantics
transactionally. Index `(status, severity)`, `(repository_name, status)` and
`(scanner, last_detected_at)` to match the query patterns the repository
interface already expresses.

---

## Mock data

Seeded when `SECURITY_DATA_SOURCE` is unset or `mock` (the default); set
`SECURITY_DATA_SOURCE=live` to start empty.

Mock content lives only in `src/lib/security/mock/`, is labelled **MOCK DATA** in
the sidebar, and contains no real credentials. It is scanner-*native* payloads
replayed through the real adapters across three timestamps (T-21d, T-10d, now),
so the seeded dashboard exercises parsing, fingerprinting, auto-resolution and
MTTR rather than displaying hand-written findings. No production code path
imports it.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SECURITY_INGEST_TOKEN` | unset | Bearer token for `POST /api/security/scans`. Required in production. |
| `SECURITY_DATA_SOURCE` | `mock` | `mock` seeds demo data, `live` starts empty. |

---

## Testing

```bash
npm test
```

165+ tests covering adapters (all four, native JSON and SARIF), the SARIF parser,
severity and category normalization, fingerprint determinism, deduplication, the
finding lifecycle, statistics and trend calculation, scanner health, and the
findings table's rendering, filters and detail drawer.

Fixtures in `tests/fixtures/` are sanitized and contain placeholder credentials
only. Two tests exist specifically to prove that Gitleaks and Trivy secret
findings never carry the secret value into the domain model — one of them caught
a real leak through the SARIF `message.text` field during development.

---

## Design

The interface is a dark-first **ops console**: near-black layered surfaces,
hairline borders, dense tables, IBM Plex Sans paired with IBM Plex Mono for
anything machine-generated (CVEs, rule ids, paths, counts). Colour is almost
entirely reserved for severity encoding, with a single cyan accent marking
interactive state — so a coloured pixel always means something. Motion respects
`prefers-reduced-motion`.

## Known limitations

- In-memory storage (see above).
- GitHub and Azure providers are declared and stubbed, not implemented; pages
  that would use them say so rather than showing placeholder data.
- Manual status changes (accept risk, false positive) exist in the service and
  are tested, but are not yet exposed as a UI control.
- Line-number-based fingerprints churn on unrelated edits where a scanner
  provides no stable id.
- Scan ingestion is authenticated but not rate-limited.
