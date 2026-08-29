PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS workspace_invites (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  email TEXT NOT NULL COLLATE NOCASE,
  role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
  token_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
  invited_by_user_id TEXT REFERENCES "user"("id") ON DELETE SET NULL,
  accepted_by_user_id TEXT REFERENCES "user"("id") ON DELETE SET NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  accepted_at TEXT,
  revoked_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_workspace_invites_pending_email
  ON workspace_invites(workspace_id, email)
  WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_workspace_invites_workspace
  ON workspace_invites(workspace_id, status, expires_at);

CREATE INDEX IF NOT EXISTS idx_workspace_invites_token
  ON workspace_invites(token_hash, status);

-- Store expiration in SQLite's canonical UTC datetime format even when the API inserts ISO-8601.
CREATE TRIGGER IF NOT EXISTS normalize_workspace_invite_expiry
AFTER INSERT ON workspace_invites
FOR EACH ROW
BEGIN
  UPDATE workspace_invites
  SET expires_at = datetime(NEW.expires_at)
  WHERE id = NEW.id;
END;
