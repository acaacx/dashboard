-- User accounts, sessions and login throttling.
--
-- Until now the application had no user authentication: anyone who could reach
-- the dashboard could move a CRITICAL finding to FALSE_POSITIVE, and a risk
-- acceptance carried a justification but no signature.
--
-- Passwords are stored as self-describing scrypt strings
-- (scrypt$N$r$p$salt$hash) so cost parameters can be raised later without
-- invalidating existing rows. Nothing here ever stores a plaintext password.
--
-- `sessions.token_hash` is the SHA-256 of the token in the user's cookie, never
-- the token. A dump of this table yields no usable sessions.
--
-- `role` is written by provisioning but not yet read by any decision. Shipping
-- the column now avoids a later backfill, where defaulting everyone to APPROVER
-- would grant exactly what the role split exists to withhold and defaulting
-- everyone to VIEWER would lock out every existing account.

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('VIEWER', 'APPROVER')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Sweeping expired sessions is a range scan over this index.
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);

-- Listing "who has sessions open" and cascading deletes both walk this.
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id);

-- Fixed-window login throttle. Keyed on the submitted email whether or not an
-- account exists, so the refusal message reveals nothing about which is which.
CREATE TABLE IF NOT EXISTS login_attempts (
  email             TEXT PRIMARY KEY,
  window_started_at TIMESTAMPTZ NOT NULL,
  count             INTEGER NOT NULL
);
