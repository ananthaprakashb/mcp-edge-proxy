ALTER TABLE gateways
ADD COLUMN connection_mode TEXT NOT NULL DEFAULT 'public'
CHECK (connection_mode IN ('public', 'cloudflare_access'));

CREATE INDEX IF NOT EXISTS idx_gateways_account_connection_mode
ON gateways(account_id, connection_mode);
