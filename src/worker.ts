import { handleAppApi } from "./app-api";
import { createAuth } from "./auth";
import { handleStripeWebhook } from "./billing-webhook";
import { verifyCapabilityToken } from "./capability";
import { handleCollaborationApi } from "./collaboration-api";
import edgeWorker from "./index";
import { capabilitySigningKeyring, upstreamEncryptionKeyring } from "./keyring";
import { handleSecretLifecycleApi } from "./secret-lifecycle-api";
import type { Env, ExecutionContextLike } from "./types";

function bearerToken(request: Request): string | null {
  const value = request.headers.get("authorization");
  if (!value) return null;
  return /^Bearer\s+(.+)$/i.exec(value)?.[1] ?? null;
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
      if (gatewayCreate) await markCreatedGatewayVersion(response, env);
      return response;
    }

    const runtimeEnv = await runtimeEnvForEdge(request, env, path);
    const response = await edgeWorker.fetch(request, runtimeEnv, ctx);
    if (request.method === "POST" && path === "/v1/control/gateways") {
      await markCreatedGatewayVersion(response, env);
    }
    return response;
  },
};
