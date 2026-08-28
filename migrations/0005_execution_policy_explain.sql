ALTER TABLE api_keys ADD COLUMN execution_mode TEXT NOT NULL DEFAULT 'direct'
  CHECK (execution_mode IN ('direct', 'capability_required'));

ALTER TABLE traces ADD COLUMN auth_mode TEXT;
ALTER TABLE traces ADD COLUMN capability_jti TEXT;
ALTER TABLE traces ADD COLUMN policy_reason TEXT;
ALTER TABLE traces ADD COLUMN policy_method_rule TEXT;
ALTER TABLE traces ADD COLUMN policy_name_rule TEXT;

CREATE INDEX IF NOT EXISTS idx_traces_auth_mode_created
  ON traces(account_id, auth_mode, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_api_keys_execution_mode
  ON api_keys(account_id, execution_mode, revoked_at);
