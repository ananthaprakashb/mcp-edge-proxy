import type { D1Database } from "./types";

export async function listContextDocumentAccess(
  db: D1Database,
  accountId: string,
  documentKey: string,
  limit = 100,
): Promise<Record<string, unknown>[]> {
  const result = await db
    .prepare(
      `SELECT l.id, l.document_key, l.document_version, l.content_hash, l.gateway_id,
              g.name AS gateway_name, l.api_key_id, k.name AS api_key_name,
              l.operation, l.requested_path, l.decision, l.reason, l.capability_jti, l.created_at
       FROM context_document_access_log l
       JOIN gateways g ON g.id = l.gateway_id
       LEFT JOIN api_keys k ON k.id = l.api_key_id
       WHERE l.account_id = ? AND l.document_key = ?
       ORDER BY datetime(l.created_at) DESC, l.id DESC
       LIMIT ?`,
    )
    .bind(accountId, documentKey, Math.max(1, Math.min(250, limit)))
    .all<Record<string, unknown>>();
  return result.results ?? [];
}
