import type { AccountRow, ApiKeyAuthRow, D1Database, ExecutionMode, GatewayRow, TraceRecord } from "./types";

export async function createAccount(
  db: D1Database,
  account: Pick<AccountRow, "id" | "name" | "plan" | "subscription_status">,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO accounts (id, name, plan, subscription_status)
       VALUES (?, ?, ?, ?)`,
    )
    .bind(account.id, account.name, account.plan, account.subscription_status)
    .run();
}

export async function createGateway(
  db: D1Database,
  gateway: {
    id: string;
    accountId: string;
    name: string;
    upstreamUrl: string;
    upstreamHeadersCiphertext: string | null;
    upstreamHeadersIv: string | null;
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO gateways
       (id, account_id, name, upstream_url, upstream_headers_ciphertext, upstream_headers_iv)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      gateway.id,
      gateway.accountId,
      gateway.name,
      gateway.upstreamUrl,
      gateway.upstreamHeadersCiphertext,
      gateway.upstreamHeadersIv,
    )
    .run();
}

export async function createApiKey(
  db: D1Database,
  key: {
    id: string;
    accountId: string;
    gatewayId: string;
    name: string;
    secretHash: string;
    keyPrefix: string;
    allowedMethods: string[];
    allowedNames: string[];
    executionMode?: ExecutionMode;
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO api_keys
       (id, account_id, gateway_id, name, secret_hash, key_prefix, allowed_methods, allowed_names, execution_mode)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      key.id,
      key.accountId,
      key.gatewayId,
      key.name,
      key.secretHash,
      key.keyPrefix,
      JSON.stringify(key.allowedMethods),
      JSON.stringify(key.allowedNames),
      key.executionMode ?? "direct",
    )
    .run();
}

export async function updateApiKeyExecutionMode(
  db: D1Database,
  keyId: string,
  executionMode: ExecutionMode,
): Promise<void> {
  await db
    .prepare(`UPDATE api_keys SET execution_mode = ? WHERE id = ? AND revoked_at IS NULL`)
    .bind(executionMode, keyId)
    .run();
}

export async function getGateway(db: D1Database, gatewayId: string): Promise<GatewayRow | null> {
  return db
    .prepare(
      `SELECT id, account_id, name, upstream_url, upstream_headers_ciphertext,
              upstream_headers_iv, enabled
       FROM gateways WHERE id = ?`,
    )
    .bind(gatewayId)
    .first<GatewayRow>();
}

export async function getApiKeyForGateway(
  db: D1Database,
  gatewayId: string,
  secretHash: string,
): Promise<ApiKeyAuthRow | null> {
  return db
    .prepare(
      `SELECT k.id AS key_id, k.account_id, k.gateway_id, k.allowed_methods, k.allowed_names,
              k.execution_mode, a.plan, a.subscription_status
       FROM api_keys k
       JOIN accounts a ON a.id = k.account_id
       JOIN gateways g ON g.id = k.gateway_id AND g.account_id = k.account_id
       WHERE k.gateway_id = ? AND k.secret_hash = ? AND k.revoked_at IS NULL`,
    )
    .bind(gatewayId, secretHash)
    .first<ApiKeyAuthRow>();
}

export async function getApiKeyByIdForGateway(
  db: D1Database,
  gatewayId: string,
  keyId: string,
): Promise<ApiKeyAuthRow | null> {
  return db
    .prepare(
      `SELECT k.id AS key_id, k.account_id, k.gateway_id, k.allowed_methods, k.allowed_names,
              k.execution_mode, a.plan, a.subscription_status
       FROM api_keys k
       JOIN accounts a ON a.id = k.account_id
       JOIN gateways g ON g.id = k.gateway_id AND g.account_id = k.account_id
       WHERE k.gateway_id = ? AND k.id = ? AND k.revoked_at IS NULL`,
    )
    .bind(gatewayId, keyId)
    .first<ApiKeyAuthRow>();
}

export async function revokeApiKey(db: D1Database, keyId: string): Promise<void> {
  await db
    .prepare(`UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL`)
    .bind(keyId)
    .run();
}

export async function insertTrace(db: D1Database, trace: TraceRecord): Promise<void> {
  await db
    .prepare(
      `INSERT INTO traces
       (id, account_id, gateway_id, api_key_id, request_id, mcp_method, mcp_name,
        decision, status_code, duration_ms, request_bytes, response_bytes, auth_mode,
        capability_jti, policy_reason, policy_method_rule, policy_name_rule)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      trace.id,
      trace.accountId,
      trace.gatewayId,
      trace.apiKeyId,
      trace.requestId,
      trace.mcpMethod,
      trace.mcpName,
      trace.decision,
      trace.statusCode,
      trace.durationMs,
      trace.requestBytes,
      trace.responseBytes,
      trace.authMode ?? null,
      trace.capabilityJti ?? null,
      trace.policyReason ?? null,
      trace.policyMethodRule ?? null,
      trace.policyNameRule ?? null,
    )
    .run();
}

export async function listTraces(
  db: D1Database,
  gatewayId: string,
  limit: number,
): Promise<Record<string, unknown>[]> {
  const result = await db
    .prepare(
      `SELECT id, request_id, gateway_id, api_key_id, mcp_method, mcp_name, decision,
              status_code, duration_ms, request_bytes, response_bytes, auth_mode,
              capability_jti, policy_reason, policy_method_rule, policy_name_rule, created_at
       FROM traces
       WHERE gateway_id = ?
       ORDER BY created_at DESC
       LIMIT ?`,
    )
    .bind(gatewayId, limit)
    .all<Record<string, unknown>>();
  return result.results ?? [];
}
