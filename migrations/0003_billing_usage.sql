PRAGMA foreign_keys = ON;

-- Exact monthly request accounting. This is the source of truth for plan usage;
-- Cloudflare rate-limit bindings remain abuse controls only.
CREATE TABLE IF NOT EXISTS usage_monthly (
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  usage_month TEXT NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (account_id, usage_month)
);
CREATE INDEX IF NOT EXISTS idx_usage_monthly_month ON usage_monthly(usage_month, account_id);

-- Stripe webhook delivery idempotency. Failed handlers remove their claim so Stripe
-- retries can be processed safely.
CREATE TABLE IF NOT EXISTS stripe_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('processing', 'processed')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  processed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_accounts_billing_customer ON accounts(billing_customer_id);
CREATE INDEX IF NOT EXISTS idx_accounts_billing_subscription ON accounts(billing_subscription_id);

ALTER TABLE accounts ADD COLUMN billing_price_id TEXT;
ALTER TABLE accounts ADD COLUMN billing_period_end TEXT;
ALTER TABLE accounts ADD COLUMN billing_cancel_at_period_end INTEGER NOT NULL DEFAULT 0;
