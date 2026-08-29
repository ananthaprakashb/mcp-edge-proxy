import type { AccountRow, ApiKeyAuthRow, D1Database, ExecutionMode, GatewayRow, TraceRecord, UpstreamConnectionMode } from "./types";

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
    upstreamSecretVersion?: number;
    connectionMode?: UpstreamConnectionMode;
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO gateways
       (id, account_id, name, upstream_url, upstream_headers_ciphertext, upstream_headers_iv,
        upstream_secret_version, credentials_rotated_at, connection_mode)
       VALUES (?, ?, ?, ?, ?, ?, ?, CASE WHEN ? IS NULL THEN NULL ELSE datetime('now') END, ?)`,
    )
    .bind(
      gateway.id,
      gateway.accountId,
      gateway.name,
      gateway.upstreamUrl,
      gateway.upstreamHeadersCiphertext,
      gateway.upstreamHeadersIv,
      gateway.upstreamSecretVersion ?? 1,
      gateway.upstreamHeadersCiphertext,
      gateway.connectionMode ?? "public",
    )
    .run();
}

export async function rotateGatewayCredentials(
  db: D1Database,
  input: { gatewayId: string; ciphertext: string | null; iv: string | null; version: number },
): Promise<void> {
  await db
    .prepare(
      `UPDATE gateways
       SET upstream_headers_ciphertext = ?, upstream_headers_iv = ?, upstream_secret_version = ?,
           credentials_rotated_at = datetime('now'), updated_at = datetime('now')
       WHERE id = ?`,
    )
    .bind(input.ciphertext, input.iv, input.version, input.gatewayId)
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
  await db.batch([
    db
      .prepare(
        `INSERT INTO api_keys
         (id, account_id, gateway_id, name, secret_hash, key_prefix, allowed_methods, allowed_names,
          execution_mode, secret_version, secret_rotated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, datetime('now'))`,
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
      ),
    db
      .prepare(
        `INSERT INTO api_key_secrets
         (id, api_key_id, secret_hash, key_prefix, version)
         VALUES (?, ?, ?, ?, 1)`,
      )
      .bind(`${key.id}:v1`, key.id, key.secretHash, key.keyPrefix),
  ]);
}

export async function rotateApiKeySecret(
  db: D1Database,
  input: {
    keyId: string;
    secretHash: string;
    keyPrefix: string;
    overlapSeconds: number;
  },
): Promise<{ version: number; previousValidUntil: string | null }> {
  const current = await db
    .prepare(`SELECT secret_version FROM api_keys WHERE id = ? AND revoked_at IS NULL`)
    .bind(input.keyId)
    .first<{ secret_version: number }>();
  if (!current) throw new Error("Agent key not found or revoked");

  const version = Number(current.secret_version) + 1;
  const previousValidUntil = input.overlapSeconds > 0
    ? new Date(Date.now() + input.overlapSeconds * 1000).toISOString()
    : new Date().toISOString();

  await db.batch([
    db
      .prepare(
        `UPDATE api_key_secrets
         SET valid_until = ?, revoked_at = CASE WHEN ? = 0 THEN datetime('now') ELSE revoked_at END
         WHERE api_key_id = ? AND revoked_at IS NULL AND valid_until IS NULL`,
      )
      .bind(previousValidUntil, input.overlapSeconds, input.keyId),
    db
      .prepare(
        `INSERT INTO api_key_secrets
         (id, api_key_id, secret_hash, key_prefix, version)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(`${input.keyId}:v${version}`, input.keyId, input.secretHash, input.keyPrefix, version),
    db
      .prepare(
        `UPDATE api_keys
         SET secret_hash = ?, key_prefix = ?, secret_version = ?, secret_rotated_at = datetime('now')
         WHERE id = ? AND revoked_at IS NULL`,
      )
      .bind(input.secretHash, input.keyPrefix, version, input.keyId),
  ]);

  return { version, previousValidUntil: input.overlapSeconds > 0 ? previousValidUntil : null };
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
              upstream_headers_iv, upstream_secret_version, credentials_rotated_at,
              connection_mode, enabled
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
              k.execution_mode, s.version AS secret_version, a.plan, a.subscription_status
       FROM api_key_secrets s
       JOIN api_keys k ON k.id = s.api_key_id
       JOIN accounts a ON a.id = k.account_id
       JOIN gateways g ON g.id = k.gateway_id AND g.account_id = k.account_id
       WHERE k.gateway_id = ? AND s.secret_hash = ? AND k.revoked_at IS NULL
         AND s.revoked_at IS NULL
         AND (s.valid_until IS NULL OR datetime(s.valid_until) > datetime('now'))`,
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
              k.execution_mode, k.secret_version, a.plan, a.subscription_status
       FROM api_keys k
       JOIN accounts a ON a.id = k.account_id
       JOIN gateways g ON g.id = k.gateway_id AND g.account_id = k.account_id
       WHERE k.gateway_id = ? AND k.id = ? AND k.revoked_at IS NULL`,
    )
    .bind(gatewayId, keyId)
    .first<ApiKeyAuthRow>();
}

export async function revokeApiKey(db: D1Database, keyId: string): Promise<void> {
  await db.batch([
    db
      .prepare(`UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL`)
      .bind(keyId),
    db
      .prepare(`UPDATE api_key_secrets SET revoked_at = datetime('now') WHERE api_key_id = ? AND revoked_at IS NULL`)
      .bind(keyId),
  ]);
}

export async function insertSecurityEvent(
  db: D1Database,
  event: {
    accountId: string;
    workspaceId?: string | null;
    actorUserId?: string | null;
    eventType: string;
    targetType: string;
    targetId: string;
    metadata?: Record<string, unknown>;
  },
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO security_events
       (id, account_id, workspace_id, actor_user_id, event_type, target_type, target_id, metadata_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      crypto.randomUUID(),
      event.accountId,
      event.workspaceId ?? null,
      event.actorUserId ?? null,
      event.eventType,
      event.targetType,
      event.targetId,
      JSON.stringify(event.metadata ?? {}),
    )
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
