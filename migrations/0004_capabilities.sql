PRAGMA foreign_keys = ON;

-- Distributed, fail-closed replay protection for short-lived MCP capability tokens.
-- A JTI is inserted only when a capability is consumed. The primary key makes
-- replay prevention atomic across Worker isolates and regions through D1.
CREATE TABLE IF NOT EXISTS capability_replays (
  jti TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  consumed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_capability_replays_expiry
  ON capability_replays(expires_at);
CREATE INDEX IF NOT EXISTS idx_capability_replays_account
  ON capability_replays(account_id, consumed_at DESC);
