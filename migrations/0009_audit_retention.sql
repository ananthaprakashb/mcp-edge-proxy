PRAGMA foreign_keys = ON;

ALTER TABLE security_events ADD COLUMN chain_sequence INTEGER;
ALTER TABLE security_events ADD COLUMN previous_hash TEXT;
ALTER TABLE security_events ADD COLUMN event_hash TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_security_events_account_chain
  ON security_events(account_id, chain_sequence)
  WHERE chain_sequence IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_events_account_type_created
  ON security_events(account_id, event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_account_actor_created
  ON security_events(account_id, actor_user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_chain_anchors (
  account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  pruned_through_sequence INTEGER NOT NULL DEFAULT 0,
  pruned_through_hash TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS retention_runs (
  id TEXT PRIMARY KEY,
  trigger_type TEXT NOT NULL CHECK (trigger_type IN ('scheduled', 'manual')),
  requested_by_user_id TEXT REFERENCES "user"(id) ON DELETE SET NULL,
  account_id TEXT REFERENCES accounts(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
  scheduled_time TEXT,
  accounts_processed INTEGER NOT NULL DEFAULT 0,
  traces_deleted INTEGER NOT NULL DEFAULT 0,
  audit_events_deleted INTEGER NOT NULL DEFAULT 0,
  integrity_failures INTEGER NOT NULL DEFAULT 0,
  error_message TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_retention_runs_account_started
  ON retention_runs(account_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_retention_runs_status_started
  ON retention_runs(status, started_at DESC);
