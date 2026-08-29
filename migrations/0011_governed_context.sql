PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS context_documents (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  document_key TEXT NOT NULL,
  title TEXT NOT NULL,
  format TEXT NOT NULL CHECK (format IN ('json', 'yaml', 'markdown', 'text', 'okf')),
  schema_name TEXT,
  schema_version TEXT,
  source_label TEXT,
  version INTEGER NOT NULL,
  content_hash TEXT NOT NULL,
  byte_size INTEGER NOT NULL,
  raw_content TEXT NOT NULL,
  normalized_json TEXT,
  effective_at TEXT,
  expires_at TEXT,
  superseded_at TEXT,
  created_by_user_id TEXT REFERENCES "user"(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(account_id, document_key, version)
);

CREATE INDEX IF NOT EXISTS idx_context_documents_account_key_version
  ON context_documents(account_id, document_key, version DESC);
CREATE INDEX IF NOT EXISTS idx_context_documents_account_hash
  ON context_documents(account_id, content_hash);
CREATE INDEX IF NOT EXISTS idx_context_documents_workspace_created
  ON context_documents(workspace_id, created_at DESC);

CREATE TABLE IF NOT EXISTS context_document_policies (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  document_key TEXT NOT NULL,
  gateway_id TEXT REFERENCES gateways(id) ON DELETE CASCADE,
  api_key_id TEXT REFERENCES api_keys(id) ON DELETE CASCADE,
  allowed_paths_json TEXT NOT NULL DEFAULT '["*"]',
  allowed_operations_json TEXT NOT NULL DEFAULT '["read","list"]',
  created_by_user_id TEXT REFERENCES "user"(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_context_document_policies_lookup
  ON context_document_policies(account_id, document_key, gateway_id, api_key_id);

CREATE TABLE IF NOT EXISTS context_document_access_log (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  workspace_id TEXT REFERENCES workspaces(id) ON DELETE SET NULL,
  document_id TEXT REFERENCES context_documents(id) ON DELETE SET NULL,
  document_key TEXT NOT NULL,
  document_version INTEGER NOT NULL,
  content_hash TEXT NOT NULL,
  gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  api_key_id TEXT REFERENCES api_keys(id) ON DELETE SET NULL,
  operation TEXT NOT NULL CHECK (operation IN ('read', 'list')),
  requested_path TEXT,
  decision TEXT NOT NULL CHECK (decision IN ('allowed', 'denied')),
  reason TEXT NOT NULL,
  capability_jti TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_context_document_access_account_created
  ON context_document_access_log(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_context_document_access_document_created
  ON context_document_access_log(document_key, created_at DESC);
