PRAGMA foreign_keys = ON;

ALTER TABLE gateways ADD COLUMN upstream_secret_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE gateways ADD COLUMN credentials_rotated_at TEXT;

ALTER TABLE api_keys ADD COLUMN secret_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE api_keys ADD COLUMN secret_rotated_at TEXT;

UPDATE api_keys SET secret_rotated_at = created_at WHERE secret_rotated_at IS NULL;
UPDATE gateways
SET credentials_rotated_at = created_at
WHERE credentials_rotated_at IS NULL AND upstream_headers_ciphertext IS NOT NULL;

CREATE TABLE IF NOT EXISTS api_key_secrets (
  id TEXT PRIMARY KEY,
  api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  secret_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  valid_until TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(api_key_id, version)
);

INSERT OR IGNORE INTO api_key_secrets
  (id, api_key_id, secret_hash, key_prefix, version, created_at)
SELECT id || ':v1', id, secret_hash, key_prefix, 1, created_at
FROM api_keys;

CREATE INDEX IF NOT EXISTS idx_api_key_secrets_auth
  ON api_key_secrets(secret_hash, api_key_id, valid_until, revoked_at);
CREATE INDEX IF NOT EXISTS idx_api_key_secrets_key_version
  ON api_key_secrets(api_key_id, version DESC);

CREATE TABLE IF NOT EXISTS security_events (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  workspace_id TEXT REFERENCES workspaces(id) ON DELETE SET NULL,
  actor_user_id TEXT REFERENCES "user"(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_security_events_account_created
  ON security_events(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_target
  ON security_events(target_type, target_id, created_at DESC);
