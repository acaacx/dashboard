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
