import type { D1Database } from "./types";

export interface ContextDocumentRow {
  id: string;
  account_id: string;
  workspace_id: string;
  document_key: string;
  title: string;
  format: string;
  schema_name: string | null;
  schema_version: string | null;
  source_label: string | null;
  version: number;
  content_hash: string;
  byte_size: number;
  raw_content: string;
  normalized_json: string | null;
  effective_at: string | null;
  expires_at: string | null;
  superseded_at: string | null;
  created_by_user_id: string | null;
  created_at: string;
}

export interface ContextPolicyRow {
  id: string;
  document_key: string;
  gateway_id: string | null;
  api_key_id: string | null;
  allowed_paths_json: string;
  allowed_operations_json: string;
  created_at: string;
}

export async function findDuplicateContextDocument(
  db: D1Database,
  accountId: string,
  contentHash: string,
): Promise<Pick<ContextDocumentRow, "id" | "document_key" | "version" | "content_hash"> | null> {
  return db
    .prepare(
      `SELECT id, document_key, version, content_hash
       FROM context_documents
       WHERE account_id = ? AND content_hash = ?
       ORDER BY datetime(created_at) DESC
       LIMIT 1`,
    )
    .bind(accountId, contentHash)
    .first<Pick<ContextDocumentRow, "id" | "document_key" | "version" | "content_hash">>();
}

export async function createContextDocument(
  db: D1Database,
  input: {
    accountId: string;
    workspaceId: string;
    documentKey: string;
    title: string;
    format: string;
    schemaName?: string | null;
    schemaVersion?: string | null;
    sourceLabel?: string | null;
    contentHash: string;
    byteSize: number;
    rawContent: string;
    normalizedJson: string;
    effectiveAt?: string | null;
    expiresAt?: string | null;
    createdByUserId?: string | null;
  },
): Promise<ContextDocumentRow> {
  const current = await db
    .prepare(
      `SELECT COALESCE(MAX(version), 0) AS version
       FROM context_documents
       WHERE account_id = ? AND document_key = ?`,
    )
    .bind(input.accountId, input.documentKey)
    .first<{ version: number }>();
  const version = Number(current?.version ?? 0) + 1;
  const id = crypto.randomUUID();

  await db.batch([
    db
      .prepare(
        `UPDATE context_documents
         SET superseded_at = datetime('now')
         WHERE account_id = ? AND document_key = ? AND superseded_at IS NULL`,
      )
      .bind(input.accountId, input.documentKey),
    db
      .prepare(
        `INSERT INTO context_documents
         (id, account_id, workspace_id, document_key, title, format, schema_name, schema_version,
          source_label, version, content_hash, byte_size, raw_content, normalized_json,
          effective_at, expires_at, created_by_user_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        id,
        input.accountId,
        input.workspaceId,
        input.documentKey,
        input.title,
        input.format,
        input.schemaName ?? null,
        input.schemaVersion ?? null,
        input.sourceLabel ?? null,
        version,
        input.contentHash,
        input.byteSize,
        input.rawContent,
        input.normalizedJson,
        input.effectiveAt ?? null,
        input.expiresAt ?? null,
        input.createdByUserId ?? null,
      ),
  ]);

  const row = await db.prepare(`SELECT * FROM context_documents WHERE id = ?`).bind(id).first<ContextDocumentRow>();
  if (!row) throw new Error("Document creation did not persist");
  return row;
}

export async function listLatestContextDocuments(db: D1Database, accountId: string): Promise<ContextDocumentRow[]> {
  const result = await db
    .prepare(
      `SELECT id, account_id, workspace_id, document_key, title, format, schema_name, schema_version,
              source_label, version, content_hash, byte_size, raw_content, normalized_json,
              effective_at, expires_at, superseded_at, created_by_user_id, created_at
       FROM context_documents
       WHERE account_id = ? AND superseded_at IS NULL
       ORDER BY datetime(created_at) DESC, document_key ASC
       LIMIT 250`,
    )
    .bind(accountId)
    .all<ContextDocumentRow>();
  return result.results ?? [];
}

export async function listContextDocumentVersions(
  db: D1Database,
  accountId: string,
  documentKey: string,
): Promise<ContextDocumentRow[]> {
  const result = await db
    .prepare(
      `SELECT id, account_id, workspace_id, document_key, title, format, schema_name, schema_version,
              source_label, version, content_hash, byte_size, raw_content, normalized_json,
              effective_at, expires_at, superseded_at, created_by_user_id, created_at
       FROM context_documents
       WHERE account_id = ? AND document_key = ?
       ORDER BY version DESC
       LIMIT 100`,
    )
    .bind(accountId, documentKey)
    .all<ContextDocumentRow>();
  return result.results ?? [];
}

export async function getLatestContextDocument(
  db: D1Database,
  accountId: string,
  documentKey: string,
): Promise<ContextDocumentRow | null> {
  return db
    .prepare(
      `SELECT id, account_id, workspace_id, document_key, title, format, schema_name, schema_version,
              source_label, version, content_hash, byte_size, raw_content, normalized_json,
              effective_at, expires_at, superseded_at, created_by_user_id, created_at
       FROM context_documents
       WHERE account_id = ? AND document_key = ? AND superseded_at IS NULL
       ORDER BY version DESC
       LIMIT 1`,
    )
    .bind(accountId, documentKey)
    .first<ContextDocumentRow>();
}

export async function grantContextDocumentPolicy(
  db: D1Database,
  input: {
    accountId: string;
    workspaceId: string;
    documentKey: string;
    gatewayId?: string | null;
    apiKeyId?: string | null;
    allowedPaths: string[];
    allowedOperations: string[];
    createdByUserId?: string | null;
  },
): Promise<string> {
  if (input.gatewayId) {
    const gateway = await db
      .prepare(`SELECT id FROM gateways WHERE id = ? AND account_id = ?`)
      .bind(input.gatewayId, input.accountId)
      .first<{ id: string }>();
    if (!gateway) throw new Error("gatewayId does not belong to this workspace");
  }
  if (input.apiKeyId) {
    const key = await db
      .prepare(`SELECT id, gateway_id FROM api_keys WHERE id = ? AND account_id = ? AND revoked_at IS NULL`)
      .bind(input.apiKeyId, input.accountId)
      .first<{ id: string; gateway_id: string }>();
    if (!key) throw new Error("apiKeyId does not belong to this workspace or is revoked");
    if (input.gatewayId && key.gateway_id !== input.gatewayId) throw new Error("apiKeyId does not belong to gatewayId");
  }

  const id = crypto.randomUUID();
  await db
    .prepare(
      `INSERT INTO context_document_policies
       (id, account_id, workspace_id, document_key, gateway_id, api_key_id,
        allowed_paths_json, allowed_operations_json, created_by_user_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      id,
      input.accountId,
      input.workspaceId,
      input.documentKey,
      input.gatewayId ?? null,
      input.apiKeyId ?? null,
      JSON.stringify(input.allowedPaths),
      JSON.stringify(input.allowedOperations),
      input.createdByUserId ?? null,
    )
    .run();
  return id;
}

export async function revokeContextDocumentPolicy(db: D1Database, accountId: string, policyId: string): Promise<void> {
  await db.prepare(`DELETE FROM context_document_policies WHERE id = ? AND account_id = ?`).bind(policyId, accountId).run();
}

export async function listContextDocumentPolicies(
  db: D1Database,
  accountId: string,
  documentKey?: string | null,
): Promise<ContextPolicyRow[]> {
  const result = documentKey
    ? await db
        .prepare(
          `SELECT id, document_key, gateway_id, api_key_id, allowed_paths_json, allowed_operations_json, created_at
           FROM context_document_policies
           WHERE account_id = ? AND document_key = ?
           ORDER BY datetime(created_at) DESC`,
        )
        .bind(accountId, documentKey)
        .all<ContextPolicyRow>()
    : await db
        .prepare(
          `SELECT id, document_key, gateway_id, api_key_id, allowed_paths_json, allowed_operations_json, created_at
           FROM context_document_policies
           WHERE account_id = ?
           ORDER BY datetime(created_at) DESC
           LIMIT 500`,
        )
        .bind(accountId)
        .all<ContextPolicyRow>();
  return result.results ?? [];
}

export async function matchingContextPolicies(
  db: D1Database,
  accountId: string,
  documentKey: string,
  gatewayId: string,
  apiKeyId: string,
): Promise<ContextPolicyRow[]> {
  const result = await db
    .prepare(
      `SELECT id, document_key, gateway_id, api_key_id, allowed_paths_json, allowed_operations_json, created_at
       FROM context_document_policies
       WHERE account_id = ? AND document_key = ?
         AND (gateway_id IS NULL OR gateway_id = ?)
         AND (api_key_id IS NULL OR api_key_id = ?)
       ORDER BY
         CASE WHEN api_key_id IS NULL THEN 1 ELSE 0 END ASC,
         CASE WHEN gateway_id IS NULL THEN 1 ELSE 0 END ASC,
         datetime(created_at) DESC`,
    )
    .bind(accountId, documentKey, gatewayId, apiKeyId)
    .all<ContextPolicyRow>();
  return result.results ?? [];
}

export async function recordContextDocumentAccess(
  db: D1Database,
  input: {
    accountId: string;
    workspaceId?: string | null;
    documentId?: string | null;
    documentKey: string;
    documentVersion: number;
    contentHash: string;
    gatewayId: string;
    apiKeyId?: string | null;
    operation: "read" | "list";
    requestedPath?: string | null;
    decision: "allowed" | "denied";
    reason: string;
    capabilityJti?: string | null;
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO context_document_access_log
       (id, account_id, workspace_id, document_id, document_key, document_version, content_hash,
        gateway_id, api_key_id, operation, requested_path, decision, reason, capability_jti)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      crypto.randomUUID(),
      input.accountId,
      input.workspaceId ?? null,
      input.documentId ?? null,
      input.documentKey,
      input.documentVersion,
      input.contentHash,
      input.gatewayId,
      input.apiKeyId ?? null,
      input.operation,
      input.requestedPath ?? null,
      input.decision,
      input.reason,
      input.capabilityJti ?? null,
    )
    .run();

  await db
    .prepare(
      `DELETE FROM context_document_access_log
       WHERE account_id = ? AND id NOT IN (
         SELECT id FROM context_document_access_log
         WHERE account_id = ?
         ORDER BY datetime(created_at) DESC, id DESC
         LIMIT 5000
       )`,
    )
    .bind(input.accountId, input.accountId)
    .run();
}
