import { handleAppApi } from "./app-api";
import { createAuth } from "./auth";
import { handleStripeWebhook } from "./billing-webhook";
import { verifyCapabilityToken } from "./capability";
import { handleCollaborationApi } from "./collaboration-api";
import { insertSecurityEvent } from "./db";
import edgeWorker from "./index";
import { capabilitySigningKeyring, upstreamEncryptionKeyring } from "./keyring";
import {
  validateRedirectTarget,
  validateResolvedNetworkTarget,
  type NetworkValidationResult,
} from "./network-policy";
import { handleSecretLifecycleApi } from "./secret-lifecycle-api";
import type { Env, ExecutionContextLike, UpstreamConnectionMode } from "./types";

interface GatewayNetworkContext {
  id: string;
  account_id: string;
  upstream_url: string;
  connection_mode: UpstreamConnectionMode;
}

function bearerToken(request: Request): string | null {
  const value = request.headers.get("authorization");
  if (!value) return null;
  return /^Bearer\s+(.+)$/i.exec(value)?.[1] ?? null;
}

function networkEventType(validation: NetworkValidationResult, redirect = false): string {
  if (redirect) return "upstream_redirect_blocked";
  if (validation.reason === "dns_rebinding_private_target") return "upstream_dns_rebinding_blocked";
  if (validation.reason === "dns_resolution_failed" || validation.reason === "dns_unresolved") return "upstream_dns_validation_failed";
  if (validation.reason === "blocked_ip_literal" || validation.reason === "resolved_non_public_address") return "upstream_private_ip_blocked";
  return "upstream_ssrf_blocked";
}

function networkBlockResponse(validation: NetworkValidationResult, eventType: string, status = 403): Response {
  const message = eventType === "upstream_dns_validation_failed"
    ? "ContextGateway could not safely validate the upstream DNS target"
    : eventType === "upstream_redirect_blocked"
      ? "The upstream returned a redirect that violates ContextGateway network policy"
      : "ContextGateway blocked the upstream because it is not a permitted public network target";
  return new Response(JSON.stringify({
    error: {
      code: eventType,
      message,
      reason: validation.reason,
      host: validation.hostname || undefined,
    },
  }), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-contextgateway-security-reason": validation.reason ?? eventType,
    },
  });
}

async function gatewayNetworkContext(env: Env, gatewayId: string): Promise<GatewayNetworkContext | null> {
  return env.DB
    .prepare(`SELECT id, account_id, upstream_url, connection_mode FROM gateways WHERE id = ? AND enabled = 1`)
    .bind(gatewayId)
    .first<GatewayNetworkContext>();
}

function queueNetworkSecurityEvent(
  env: Env,
  ctx: ExecutionContextLike,
  gateway: GatewayNetworkContext,
  eventType: string,
  validation: NetworkValidationResult,
  phase: "configuration" | "preflight" | "redirect",
): void {
  ctx.waitUntil(insertSecurityEvent(env.DB, {
    accountId: gateway.account_id,
    eventType,
    targetType: "gateway",
    targetId: gateway.id,
    metadata: {
      phase,
      host: validation.hostname,
      reason: validation.reason,
      blockedAddress: validation.blockedAddress ?? null,
      resolvedAddresses: validation.addresses.slice(0, 8),
      changedBetweenChecks: validation.changedBetweenChecks ?? false,
      connectionMode: gateway.connection_mode,
    },
  }).catch(() => undefined));
}

async function guardGatewayExecution(
  env: Env,
  ctx: ExecutionContextLike,
  gatewayId: string,
): Promise<GatewayNetworkContext | Response | null> {
  const gateway = await gatewayNetworkContext(env, gatewayId);
  if (!gateway) return null;
  let target: URL;
  try {
    target = new URL(gateway.upstream_url);
  } catch {
    const validation: NetworkValidationResult = {
      allowed: false,
      hostname: "",
      addresses: [],
      reason: "blocked_hostname",
    };
    const eventType = "upstream_ssrf_blocked";
    queueNetworkSecurityEvent(env, ctx, gateway, eventType, validation, "preflight");
    return networkBlockResponse(validation, eventType);
  }

  const validation = await validateResolvedNetworkTarget(target);
  if (!validation.allowed) {
    const eventType = networkEventType(validation);
    queueNetworkSecurityEvent(env, ctx, gateway, eventType, validation, "preflight");
    const status = eventType === "upstream_dns_validation_failed" ? 502 : 403;
    return networkBlockResponse(validation, eventType, status);
  }
  return gateway;
}

async function validateCreatedGateway(
  response: Response,
  env: Env,
  ctx: ExecutionContextLike,
): Promise<Response | null> {
  if (response.status !== 201) return null;
  let gatewayId: string | undefined;
  try {
    const body = await response.clone().json() as { id?: string; gateway?: { id?: string } };
    gatewayId = body.id ?? body.gateway?.id;
  } catch {
    return null;
  }
  if (!gatewayId) return null;

  const gateway = await gatewayNetworkContext(env, gatewayId);
  if (!gateway) return null;
  const validation = await validateResolvedNetworkTarget(new URL(gateway.upstream_url));
  if (validation.allowed) return null;

  const eventType = networkEventType(validation);
  await insertSecurityEvent(env.DB, {
    accountId: gateway.account_id,
    eventType,
    targetType: "gateway",
    targetId: gateway.id,
    metadata: {
      phase: "configuration",
      host: validation.hostname,
      reason: validation.reason,
      blockedAddress: validation.blockedAddress ?? null,
      resolvedAddresses: validation.addresses.slice(0, 8),
      changedBetweenChecks: validation.changedBetweenChecks ?? false,
      connectionMode: gateway.connection_mode,
    },
  }).catch(() => undefined);
  await env.DB.prepare(`DELETE FROM gateways WHERE id = ?`).bind(gateway.id).run();
  const status = eventType === "upstream_dns_validation_failed" ? 502 : 400;
  return networkBlockResponse(validation, eventType, status);
}

async function guardUpstreamRedirect(
  response: Response,
  gateway: GatewayNetworkContext,
  env: Env,
  ctx: ExecutionContextLike,
): Promise<Response | null> {
  if (response.status < 300 || response.status > 399) return null;
  const location = response.headers.get("location");
  if (!location) return null;

  const { validation } = await validateRedirectTarget(new URL(gateway.upstream_url), location);
  if (validation.allowed) return null;
  const eventType = networkEventType(validation, true);
  queueNetworkSecurityEvent(env, ctx, gateway, eventType, validation, "redirect");
  return networkBlockResponse(validation, eventType, 502);
}

async function runtimeEnvForEdge(request: Request, env: Env, path: string): Promise<Env> {
  const runtimeEnv: Env = { ...env };
  const signing = capabilitySigningKeyring(env);
  const encryption = upstreamEncryptionKeyring(env);

  if (/^\/v1\/mcp\/[^/]+\/capabilities$/.test(path)) {
    runtimeEnv.CAPABILITY_SIGNING_KEY = signing.keys[signing.activeKid];
  } else if (/^\/v1\/mcp\/[^/]+$/.test(path)) {
    const token = bearerToken(request);
    if (token?.startsWith("cg_cap_")) {
      for (const key of Object.values(signing.keys)) {
        try {
          await verifyCapabilityToken(key, token);
          runtimeEnv.CAPABILITY_SIGNING_KEY = key;
          break;
        } catch {
          // The normal data-plane verifier will return the final invalid-capability response.
        }
      }
    }
  }

  const gatewayMatch = /^\/v1\/mcp\/([^/]+)(?:\/capabilities)?$/.exec(path);
  if (gatewayMatch) {
    const gateway = await env.DB
      .prepare(`SELECT upstream_secret_version FROM gateways WHERE id = ?`)
      .bind(decodeURIComponent(gatewayMatch[1]))
      .first<{ upstream_secret_version: number }>();
    if (gateway) {
      const key = encryption.keys[Number(gateway.upstream_secret_version ?? 1)];
      if (key) runtimeEnv.UPSTREAM_ENCRYPTION_KEY = key;
    }
  }

  if (request.method === "POST" && path === "/v1/control/gateways") {
    runtimeEnv.UPSTREAM_ENCRYPTION_KEY = encryption.keys[encryption.activeVersion];
  }

  return runtimeEnv;
}

async function markCreatedGatewayVersion(response: Response, env: Env): Promise<void> {
  if (response.status !== 201) return;
  const ring = upstreamEncryptionKeyring(env);
  if (ring.activeVersion === 1) return;
  try {
    const body = await response.clone().json() as { id?: string; gateway?: { id?: string } };
    const gatewayId = body.id ?? body.gateway?.id;
    if (!gatewayId) return;
    await env.DB
      .prepare(`UPDATE gateways SET upstream_secret_version = ? WHERE id = ?`)
      .bind(ring.activeVersion, gatewayId)
      .run();
  } catch {
    // Version metadata is best-effort here; normal gateway creation response is preserved.
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContextLike): Promise<Response> {
    const path = new URL(request.url).pathname;

    if (path === "/v1/billing/stripe/webhook") {
      return handleStripeWebhook(request, env);
    }

    if (path.startsWith("/api/auth/")) {
      return createAuth(env, request).handler(request);
    }

    if (path.startsWith("/v1/app/")) {
      const lifecycle = await handleSecretLifecycleApi(request, env, path);
      if (lifecycle) return lifecycle;
      const collaboration = await handleCollaborationApi(request, env, path);
      if (collaboration) return collaboration;

      const gatewayCreate = request.method === "POST" && /^\/v1\/app\/workspaces\/[^/]+\/gateways$/.test(path);
      const runtimeEnv = gatewayCreate
        ? { ...env, UPSTREAM_ENCRYPTION_KEY: upstreamEncryptionKeyring(env).keys[upstreamEncryptionKeyring(env).activeVersion] }
        : env;
      const response = await handleAppApi(request, runtimeEnv, path);
      if (gatewayCreate) {
        const blocked = await validateCreatedGateway(response, env, ctx);
        if (blocked) return blocked;
        await markCreatedGatewayVersion(response, env);
      }
      return response;
    }

    const executionMatch = /^\/v1\/mcp\/([^/]+)$/.exec(path);
    let networkGateway: GatewayNetworkContext | null = null;
    if (executionMatch) {
      const guarded = await guardGatewayExecution(env, ctx, decodeURIComponent(executionMatch[1]));
      if (guarded instanceof Response) return guarded;
      networkGateway = guarded;
    }

    const runtimeEnv = await runtimeEnvForEdge(request, env, path);
    const response = await edgeWorker.fetch(request, runtimeEnv, ctx);

    if (request.method === "POST" && path === "/v1/control/gateways") {
      const blocked = await validateCreatedGateway(response, env, ctx);
      if (blocked) return blocked;
      await markCreatedGatewayVersion(response, env);
    }

    if (networkGateway) {
      const blockedRedirect = await guardUpstreamRedirect(response, networkGateway, env, ctx);
      if (blockedRedirect) return blockedRedirect;
    }
    return response;
  },
};
