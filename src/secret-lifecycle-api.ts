import { getWorkspaceMembership, listSecurityEvents } from "./app-db";
import { createAuth } from "./auth";
import { applyConnectionCredentials } from "./connection-mode";
import { generateAgentKey, sha256Hex } from "./crypto";
import { getGateway, insertSecurityEvent, rotateApiKeySecret, rotateGatewayCredentials } from "./db";
import { encryptUpstreamSecret, publicKeyringMetadata } from "./keyring";
import { validateUpstreamHeaders } from "./security";
import type { Env } from "./types";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};
const DEFAULT_OVERLAP_SECONDS = 300;
const MAX_OVERLAP_SECONDS = 86_400;

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function errorResponse(status: number, code: string, message: string): Response {
  return json({ error: { code, message } }, status);
}

async function readJsonObject(request: Request): Promise<Record<string, unknown>> {
  const body = (await request.json()) as unknown;
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("JSON request body must be an object");
  return body as Record<string, unknown>;
}

async function userForRequest(request: Request, env: Env) {
  const session = await createAuth(env, request).api.getSession({ headers: request.headers });
  return session?.user ?? null;
}

function parseOverlapSeconds(value: unknown): number {
  if (value === undefined) return DEFAULT_OVERLAP_SECONDS;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > MAX_OVERLAP_SECONDS) {
    throw new Error(`overlapSeconds must be an integer between 0 and ${MAX_OVERLAP_SECONDS}`);
  }
  return parsed;
}

export async function handleSecretLifecycleApi(request: Request, env: Env, path: string): Promise<Response | null> {
  const securityMatch = /^\/v1\/app\/workspaces\/([^/]+)\/security$/.exec(path);
  const credentialRotateMatch = /^\/v1\/app\/workspaces\/([^/]+)\/gateways\/([^/]+)\/credentials\/rotate$/.exec(path);
  const keyRotateMatch = /^\/v1\/app\/workspaces\/([^/]+)\/gateways\/([^/]+)\/keys\/([^/]+)\/rotate$/.exec(path);
  if (!securityMatch && !credentialRotateMatch && !keyRotateMatch) return null;

  try {
    const user = await userForRequest(request, env);
    if (!user) return errorResponse(401, "unauthorized", "Sign in is required");

    const workspaceId = decodeURIComponent((securityMatch || credentialRotateMatch || keyRotateMatch)![1]);
    const membership = await getWorkspaceMembership(env.DB, workspaceId, user.id);
    if (!membership) return errorResponse(404, "workspace_not_found", "Workspace not found");

    if (securityMatch && request.method === "GET") {
      return json({
        workspace: membership,
        keyrings: publicKeyringMetadata(env),
        events: await listSecurityEvents(env.DB, membership.account_id, 100),
      });
    }

    if (membership.role !== "owner" && membership.role !== "admin") {
      return errorResponse(403, "forbidden", "Owner or admin role is required for credential rotation");
    }

    if (credentialRotateMatch && request.method === "POST") {
      const gatewayId = decodeURIComponent(credentialRotateMatch[2]);
      const gateway = await getGateway(env.DB, gatewayId);
      if (!gateway || gateway.account_id !== membership.account_id) return errorResponse(404, "gateway_not_found", "Gateway not found");

      const body = await readJsonObject(request);
      const headers = applyConnectionCredentials(
        gateway.connection_mode,
        validateUpstreamHeaders(body.upstreamHeaders),
        { accessClientId: body.accessClientId, accessClientSecret: body.accessClientSecret },
      );

      let ciphertext: string | null = null;
      let iv: string | null = null;
      let version = publicKeyringMetadata(env).upstreamEncryption.activeVersion;
      if (Object.keys(headers).length > 0) {
        const encrypted = await encryptUpstreamSecret(env, JSON.stringify(headers));
        ciphertext = encrypted.ciphertext;
        iv = encrypted.iv;
        version = encrypted.version;
      }

      await rotateGatewayCredentials(env.DB, { gatewayId, ciphertext, iv, version });
      await insertSecurityEvent(env.DB, {
        accountId: membership.account_id,
        workspaceId,
        actorUserId: user.id,
        eventType: "gateway_credentials_rotated",
        targetType: "gateway",
        targetId: gatewayId,
        metadata: { encryptionVersion: version, connectionMode: gateway.connection_mode, credentialsPresent: Object.keys(headers).length > 0 },
      });

      return json({
        gatewayId,
        encryptionVersion: version,
        rotatedAt: new Date().toISOString(),
        credentialsPresent: Object.keys(headers).length > 0,
      });
    }

    if (keyRotateMatch && request.method === "POST") {
      const gatewayId = decodeURIComponent(keyRotateMatch[2]);
      const keyId = decodeURIComponent(keyRotateMatch[3]);
      const gateway = await getGateway(env.DB, gatewayId);
      if (!gateway || gateway.account_id !== membership.account_id) return errorResponse(404, "gateway_not_found", "Gateway not found");
      const key = await env.DB
        .prepare(`SELECT id, revoked_at FROM api_keys WHERE id = ? AND gateway_id = ? AND account_id = ?`)
        .bind(keyId, gatewayId, membership.account_id)
        .first<{ id: string; revoked_at: string | null }>();
      if (!key) return errorResponse(404, "key_not_found", "Agent key not found");
      if (key.revoked_at) return errorResponse(409, "key_revoked", "A revoked key cannot be rotated");

      const body = await readJsonObject(request);
      const overlapSeconds = parseOverlapSeconds(body.overlapSeconds);
      const secret = generateAgentKey();
      const result = await rotateApiKeySecret(env.DB, {
        keyId,
        secretHash: await sha256Hex(secret),
        keyPrefix: secret.slice(0, 18),
        overlapSeconds,
      });
      await insertSecurityEvent(env.DB, {
        accountId: membership.account_id,
        workspaceId,
        actorUserId: user.id,
        eventType: "agent_key_rotated",
        targetType: "api_key",
        targetId: keyId,
        metadata: { version: result.version, overlapSeconds, previousValidUntil: result.previousValidUntil },
      });

      return json({
        key: {
          id: keyId,
          key: secret,
          keyPrefix: secret.slice(0, 18),
          version: result.version,
          previousValidUntil: result.previousValidUntil,
        },
        warning: "This plaintext agent key is shown only once. Store it before closing this response.",
      });
    }

    return errorResponse(405, "method_not_allowed", "Method not allowed for secret lifecycle route");
  } catch (error) {
    return errorResponse(400, "invalid_request", error instanceof Error ? error.message : "Invalid request");
  }
}
