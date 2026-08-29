import { insertSecurityEvent } from "./db";
import { decryptUpstreamSecret } from "./keyring";
import { validateRedirectTarget, validateResolvedNetworkTarget } from "./network-policy";
import type { D1Database, Env, UpstreamConnectionMode } from "./types";

export type GatewayHealthStatus =
  | "healthy"
  | "degraded"
  | "unreachable"
  | "auth_failure"
  | "dns_blocked"
  | "timeout"
  | "tls_failure";

export interface GatewayHealthTarget {
  id: string;
  account_id: string;
  upstream_url: string;
  upstream_headers_ciphertext: string | null;
  upstream_headers_iv: string | null;
  upstream_secret_version: number;
  connection_mode: UpstreamConnectionMode;
  health_status: GatewayHealthStatus | "unknown";
}

export interface GatewayHealthResult {
  gatewayId: string;
  status: GatewayHealthStatus;
  reason: string;
  connectionMode: UpstreamConnectionMode;
  httpStatus: number | null;
  latencyMs: number | null;
  dnsAddresses: string[];
  checkedAt: string;
}

const PROBE_TIMEOUT_MS = 8_000;
const SCHEDULED_BATCH_SIZE = 6;
const MAX_HISTORY_PER_GATEWAY = 672;

function tlsLikeError(error: unknown): boolean {
  const message = error instanceof Error ? `${error.name} ${error.message}`.toLowerCase() : String(error).toLowerCase();
  return ["tls", "ssl", "certificate", "cert", "x509"].some((needle) => message.includes(needle));
}

function timeoutLikeError(error: unknown): boolean {
  if (error instanceof DOMException && error.name === "AbortError") return true;
  const message = error instanceof Error ? `${error.name} ${error.message}`.toLowerCase() : String(error).toLowerCase();
  return message.includes("abort") || message.includes("timeout") || message.includes("timed out");
}

function statusFromNetworkReason(reason: string | undefined): GatewayHealthStatus {
  if (reason === "dns_resolution_failed" || reason === "dns_unresolved") return "unreachable";
  return "dns_blocked";
}

function statusFromHttp(status: number): { status: GatewayHealthStatus; reason: string } {
  if (status === 401 || status === 403) return { status: "auth_failure", reason: "upstream_auth_rejected" };
  if (status === 429) return { status: "degraded", reason: "upstream_rate_limited" };
  if (status >= 500) return { status: "degraded", reason: "upstream_server_error" };
  if (status === 405) return { status: "healthy", reason: "reachable_head_not_supported" };
  return { status: "healthy", reason: "reachable" };
}

async function injectedHeaders(env: Env, gateway: GatewayHealthTarget): Promise<Record<string, string>> {
  if (!gateway.upstream_headers_ciphertext || !gateway.upstream_headers_iv) return {};
  const plaintext = await decryptUpstreamSecret(env, {
    ciphertext: gateway.upstream_headers_ciphertext,
    iv: gateway.upstream_headers_iv,
    version: Number(gateway.upstream_secret_version ?? 1),
  });
  const parsed = JSON.parse(plaintext) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("credential_payload_invalid");
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof value !== "string") throw new Error("credential_payload_invalid");
    result[name] = value;
  }
  return result;
}

async function persistHealthResult(
  db: D1Database,
  gateway: GatewayHealthTarget,
  result: GatewayHealthResult,
  triggerType: "scheduled" | "manual",
): Promise<void> {
  const failed = result.status !== "healthy";
  await db.batch([
    db
      .prepare(
        `INSERT INTO gateway_health_checks
         (id, account_id, gateway_id, trigger_type, status, reason, connection_mode,
          http_status, latency_ms, dns_addresses_json, checked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        crypto.randomUUID(),
        gateway.account_id,
        gateway.id,
        triggerType,
        result.status,
        result.reason,
        gateway.connection_mode,
        result.httpStatus,
        result.latencyMs,
        JSON.stringify(result.dnsAddresses.slice(0, 8)),
        result.checkedAt,
      ),
    db
      .prepare(
        `UPDATE gateways
         SET health_status = ?, health_reason = ?, last_health_checked_at = ?,
             last_health_success_at = CASE WHEN ? = 0 THEN ? ELSE last_health_success_at END,
             last_health_failure_at = CASE WHEN ? = 1 THEN ? ELSE last_health_failure_at END,
             last_health_latency_ms = ?, last_health_http_status = ?,
             consecutive_health_failures = CASE WHEN ? = 0 THEN 0 ELSE consecutive_health_failures + 1 END,
             updated_at = datetime('now')
         WHERE id = ?`,
      )
      .bind(
        result.status,
        result.reason,
        result.checkedAt,
        failed ? 1 : 0,
        result.checkedAt,
        failed ? 1 : 0,
        result.checkedAt,
        result.latencyMs,
        result.httpStatus,
        failed ? 1 : 0,
        gateway.id,
      ),
  ]);

  await db
    .prepare(
      `DELETE FROM gateway_health_checks
       WHERE gateway_id = ?
         AND id NOT IN (
           SELECT id FROM gateway_health_checks
           WHERE gateway_id = ?
           ORDER BY datetime(checked_at) DESC, id DESC
           LIMIT ?
         )`,
    )
    .bind(gateway.id, gateway.id, MAX_HISTORY_PER_GATEWAY)
    .run();
}

async function emitHealthTransitions(
  env: Env,
  gateway: GatewayHealthTarget,
  result: GatewayHealthResult,
  triggerType: "scheduled" | "manual",
  actorUserId?: string | null,
  workspaceId?: string | null,
): Promise<void> {
  const previous = gateway.health_status;
  const metadata = {
    triggerType,
    previousStatus: previous,
    status: result.status,
    reason: result.reason,
    httpStatus: result.httpStatus,
    latencyMs: result.latencyMs,
    connectionMode: result.connectionMode,
  };

  if (result.status === "healthy" && previous !== "healthy" && previous !== "unknown") {
    await insertSecurityEvent(env.DB, {
      accountId: gateway.account_id,
      workspaceId,
      actorUserId,
      eventType: "gateway_health_recovered",
      targetType: "gateway",
      targetId: gateway.id,
      metadata,
    });
    return;
  }

  if (result.status !== "healthy" && (previous === "healthy" || previous === "unknown")) {
    await insertSecurityEvent(env.DB, {
      accountId: gateway.account_id,
      workspaceId,
      actorUserId,
      eventType: "gateway_health_failed",
      targetType: "gateway",
      targetId: gateway.id,
      metadata,
    });
  }

  if (result.status === "auth_failure" && previous !== "auth_failure") {
    await insertSecurityEvent(env.DB, {
      accountId: gateway.account_id,
      workspaceId,
      actorUserId,
      eventType: "gateway_credentials_invalid",
      targetType: "gateway",
      targetId: gateway.id,
      metadata,
    });
  }
}

export async function loadGatewayHealthTarget(
  db: D1Database,
  gatewayId: string,
  accountId?: string,
): Promise<GatewayHealthTarget | null> {
  const query = `SELECT id, account_id, upstream_url, upstream_headers_ciphertext, upstream_headers_iv,
                        upstream_secret_version, connection_mode, health_status
                 FROM gateways
                 WHERE id = ? AND enabled = 1${accountId ? " AND account_id = ?" : ""}`;
  const statement = db.prepare(query);
  return accountId
    ? statement.bind(gatewayId, accountId).first<GatewayHealthTarget>()
    : statement.bind(gatewayId).first<GatewayHealthTarget>();
}

export async function runGatewayHealthCheck(
  env: Env,
  gateway: GatewayHealthTarget,
  options: {
    triggerType: "scheduled" | "manual";
    actorUserId?: string | null;
    workspaceId?: string | null;
  },
): Promise<GatewayHealthResult> {
  const checkedAt = new Date().toISOString();
  let target: URL;
  try {
    target = new URL(gateway.upstream_url);
  } catch {
    const result: GatewayHealthResult = {
      gatewayId: gateway.id,
      status: "dns_blocked",
      reason: "invalid_upstream_url",
      connectionMode: gateway.connection_mode,
      httpStatus: null,
      latencyMs: null,
      dnsAddresses: [],
      checkedAt,
    };
    await persistHealthResult(env.DB, gateway, result, options.triggerType);
    await emitHealthTransitions(env, gateway, result, options.triggerType, options.actorUserId, options.workspaceId);
    return result;
  }

  const network = await validateResolvedNetworkTarget(target);
  if (!network.allowed) {
    const result: GatewayHealthResult = {
      gatewayId: gateway.id,
      status: statusFromNetworkReason(network.reason),
      reason: network.reason ?? "network_policy_blocked",
      connectionMode: gateway.connection_mode,
      httpStatus: null,
      latencyMs: null,
      dnsAddresses: network.addresses,
      checkedAt,
    };
    await persistHealthResult(env.DB, gateway, result, options.triggerType);
    await emitHealthTransitions(env, gateway, result, options.triggerType, options.actorUserId, options.workspaceId);
    return result;
  }

  let headers: Record<string, string>;
  try {
    headers = await injectedHeaders(env, gateway);
  } catch {
    const result: GatewayHealthResult = {
      gatewayId: gateway.id,
      status: "degraded",
      reason: "credential_decrypt_failed",
      connectionMode: gateway.connection_mode,
      httpStatus: null,
      latencyMs: null,
      dnsAddresses: network.addresses,
      checkedAt,
    };
    await persistHealthResult(env.DB, gateway, result, options.triggerType);
    await emitHealthTransitions(env, gateway, result, options.triggerType, options.actorUserId, options.workspaceId);
    return result;
  }

  const abort = new AbortController();
  const timeout = setTimeout(() => abort.abort(), PROBE_TIMEOUT_MS);
  const started = Date.now();
  try {
    const response = await fetch(target.toString(), {
      method: "HEAD",
      headers,
      redirect: "manual",
      signal: abort.signal,
    });
    const latencyMs = Math.max(0, Date.now() - started);
    let classification = statusFromHttp(response.status);

    if (response.status >= 300 && response.status <= 399) {
      const location = response.headers.get("location");
      if (location) {
        const redirect = await validateRedirectTarget(target, location);
        if (!redirect.validation.allowed) {
          const networkReason = redirect.validation.reason;
          classification = {
            status: networkReason === "blocked_ip_literal" || networkReason === "resolved_non_public_address" || networkReason === "dns_rebinding_private_target"
              ? "dns_blocked"
              : "degraded",
            reason: `redirect_blocked:${networkReason ?? "unknown"}`,
          };
        } else {
          classification = { status: "healthy", reason: "reachable_safe_redirect" };
        }
      }
    }

    const result: GatewayHealthResult = {
      gatewayId: gateway.id,
      status: classification.status,
      reason: classification.reason,
      connectionMode: gateway.connection_mode,
      httpStatus: response.status,
      latencyMs,
      dnsAddresses: network.addresses,
      checkedAt,
    };
    await persistHealthResult(env.DB, gateway, result, options.triggerType);
    await emitHealthTransitions(env, gateway, result, options.triggerType, options.actorUserId, options.workspaceId);
    return result;
  } catch (error) {
    const latencyMs = Math.max(0, Date.now() - started);
    const status: GatewayHealthStatus = timeoutLikeError(error)
      ? "timeout"
      : tlsLikeError(error)
        ? "tls_failure"
        : "unreachable";
    const result: GatewayHealthResult = {
      gatewayId: gateway.id,
      status,
      reason: status === "timeout" ? "upstream_timeout" : status === "tls_failure" ? "tls_handshake_failed" : "upstream_unreachable",
      connectionMode: gateway.connection_mode,
      httpStatus: null,
      latencyMs,
      dnsAddresses: network.addresses,
      checkedAt,
    };
    await persistHealthResult(env.DB, gateway, result, options.triggerType);
    await emitHealthTransitions(env, gateway, result, options.triggerType, options.actorUserId, options.workspaceId);
    return result;
  } finally {
    clearTimeout(timeout);
  }
}

export async function runScheduledGatewayHealthChecks(env: Env): Promise<GatewayHealthResult[]> {
  const result = await env.DB
    .prepare(
      `SELECT id, account_id, upstream_url, upstream_headers_ciphertext, upstream_headers_iv,
              upstream_secret_version, connection_mode, health_status
       FROM gateways
       WHERE enabled = 1
       ORDER BY COALESCE(datetime(last_health_checked_at), datetime('1970-01-01')) ASC, id ASC
       LIMIT ?`,
    )
    .bind(SCHEDULED_BATCH_SIZE)
    .all<GatewayHealthTarget>();

  const checks: GatewayHealthResult[] = [];
  for (const gateway of result.results ?? []) {
    checks.push(await runGatewayHealthCheck(env, gateway, { triggerType: "scheduled" }));
  }
  return checks;
}

export async function listGatewayHealthHistory(
  db: D1Database,
  gatewayId: string,
  accountId: string,
  limit = 24,
): Promise<Record<string, unknown>[]> {
  const result = await db
    .prepare(
      `SELECT id, trigger_type, status, reason, connection_mode, http_status, latency_ms,
              dns_addresses_json, checked_at
       FROM gateway_health_checks
       WHERE gateway_id = ? AND account_id = ?
       ORDER BY datetime(checked_at) DESC, id DESC
       LIMIT ?`,
    )
    .bind(gatewayId, accountId, Math.max(1, Math.min(100, limit)))
    .all<Record<string, unknown>>();
  return result.results ?? [];
}
