PRAGMA foreign_keys = ON;

ALTER TABLE gateways ADD COLUMN health_status TEXT NOT NULL DEFAULT 'unknown'
  CHECK (health_status IN ('unknown', 'healthy', 'degraded', 'unreachable', 'auth_failure', 'dns_blocked', 'timeout', 'tls_failure'));
ALTER TABLE gateways ADD COLUMN health_reason TEXT;
ALTER TABLE gateways ADD COLUMN last_health_checked_at TEXT;
ALTER TABLE gateways ADD COLUMN last_health_success_at TEXT;
ALTER TABLE gateways ADD COLUMN last_health_failure_at TEXT;
ALTER TABLE gateways ADD COLUMN last_health_latency_ms INTEGER;
ALTER TABLE gateways ADD COLUMN last_health_http_status INTEGER;
ALTER TABLE gateways ADD COLUMN consecutive_health_failures INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS gateway_health_checks (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  trigger_type TEXT NOT NULL CHECK (trigger_type IN ('scheduled', 'manual')),
  status TEXT NOT NULL
    CHECK (status IN ('healthy', 'degraded', 'unreachable', 'auth_failure', 'dns_blocked', 'timeout', 'tls_failure')),
  reason TEXT NOT NULL,
  connection_mode TEXT NOT NULL CHECK (connection_mode IN ('public', 'cloudflare_access')),
  http_status INTEGER,
  latency_ms INTEGER,
  dns_addresses_json TEXT NOT NULL DEFAULT '[]',
  checked_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gateway_health_checks_gateway_checked
  ON gateway_health_checks(gateway_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_health_checks_account_checked
  ON gateway_health_checks(account_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateways_health_schedule
  ON gateways(enabled, last_health_checked_at);
