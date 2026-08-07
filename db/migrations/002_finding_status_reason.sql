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
