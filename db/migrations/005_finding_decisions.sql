-- Append-only history of human status decisions.
--
-- The finding row keeps the current-decision snapshot (status_reason,
-- status_changed_at, status_changed_by); this table is the trail behind it.
-- Rows are inserted by recordDecision and never updated or deleted.
--
-- Unlike status_changed_by, finding_id takes a foreign key: findings are never
-- deleted (the repository has no delete method), so the FK costs nothing.
-- CASCADE states the correct behaviour for a path that is not exercised.
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
