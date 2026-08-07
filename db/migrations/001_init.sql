-- Initial schema for the DevSecOps dashboard.
--
-- `fingerprint` is the natural key: it is the deterministic identity of "this
-- problem, in this place", so ON CONFLICT (fingerprint) DO UPDATE gives the
-- same deduplication semantics the in-memory store implements in JavaScript,
-- but transactionally and across processes.
--
-- Timestamps are TIMESTAMPTZ. The domain model speaks ISO-8601 UTC strings and
-- the repository converts at the boundary, so ordering and window comparisons
-- behave identically to the in-memory implementation.

CREATE TABLE IF NOT EXISTS security_findings (
  fingerprint       TEXT PRIMARY KEY,
  id                TEXT NOT NULL UNIQUE,

  scanner           TEXT NOT NULL,
  category          TEXT NOT NULL,
  severity          TEXT NOT NULL,

  title             TEXT NOT NULL,
  description       TEXT,

  repository_id     TEXT,
  repository_name   TEXT,
  branch            TEXT,
  commit_sha        TEXT,
  application_id    TEXT,
  environment       TEXT,

  file              TEXT,
  start_line        INTEGER,
  end_line          INTEGER,

  package_name      TEXT,
  package_version   TEXT,
  fixed_version     TEXT,

  cve               TEXT,
  cwe               TEXT,
  rule_id           TEXT,

  resource          TEXT,
  azure_resource_id TEXT,
  subscription_id   TEXT,
  resource_group    TEXT,

  status            TEXT NOT NULL,

  first_detected_at TIMESTAMPTZ NOT NULL,
  last_detected_at  TIMESTAMPTZ NOT NULL,
  resolved_at       TIMESTAMPTZ,

  remediation       TEXT,
  source_url        TEXT,
  metadata          JSONB
);

-- Indexes chosen to match the query patterns the repository interface already
-- expresses: the findings table filters, the statistics breakdowns, and the
-- per-scanner resolution scope used during ingestion.
CREATE INDEX IF NOT EXISTS security_findings_status_severity_idx
  ON security_findings (status, severity);
CREATE INDEX IF NOT EXISTS security_findings_repository_status_idx
  ON security_findings (repository_name, status);
CREATE INDEX IF NOT EXISTS security_findings_scanner_last_detected_idx
  ON security_findings (scanner, last_detected_at DESC);
CREATE INDEX IF NOT EXISTS security_findings_scope_idx
  ON security_findings (scanner, repository_id, repository_name);
CREATE INDEX IF NOT EXISTS security_findings_first_detected_idx
  ON security_findings (first_detected_at);
CREATE INDEX IF NOT EXISTS security_findings_resolved_at_idx
  ON security_findings (resolved_at)
  WHERE resolved_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS scan_runs (
  id               TEXT PRIMARY KEY,
  scanner          TEXT NOT NULL,

  repository_id    TEXT,
  repository_name  TEXT,
  branch           TEXT,
  commit_sha       TEXT,

  workflow_run_id  TEXT,
  workflow_run_url TEXT,

  status           TEXT NOT NULL,

  -- When the SCAN ran (from the ingestion request), not when we received it.
  started_at       TIMESTAMPTZ NOT NULL,
  completed_at     TIMESTAMPTZ,
  -- When the dashboard normalized and stored the report.
  ingested_at      TIMESTAMPTZ,

  critical         INTEGER NOT NULL DEFAULT 0,
  high             INTEGER NOT NULL DEFAULT 0,
  medium           INTEGER NOT NULL DEFAULT 0,
  low              INTEGER NOT NULL DEFAULT 0,
  info             INTEGER NOT NULL DEFAULT 0,

  total_findings   INTEGER NOT NULL DEFAULT 0,
  duration_seconds INTEGER,
  error            TEXT
);

CREATE INDEX IF NOT EXISTS scan_runs_scanner_started_idx
  ON scan_runs (scanner, started_at DESC);
CREATE INDEX IF NOT EXISTS scan_runs_repository_idx
  ON scan_runs (repository_name, started_at DESC);
