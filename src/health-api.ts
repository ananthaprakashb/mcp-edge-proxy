import { getWorkspaceMembership } from "./app-db";
import { createAuth } from "./auth";
import {
  listGatewayHealthHistory,
  loadGatewayHealthTarget,
  runGatewayHealthCheck,
} from "./gateway-health";
import type { Env } from "./types";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function errorResponse(status: number, code: string, message: string): Response {
  return json({ error: { code, message } }, status);
}

async function requestUser(request: Request, env: Env) {
  const session = await createAuth(env, request).api.getSession({ headers: request.headers });
  return session?.user ?? null;
}

export async function handleHealthApi(request: Request, env: Env, path: string): Promise<Response | null> {
  const detailsMatch = /^\/v1\/app\/workspaces\/([^/]+)\/gateways\/([^/]+)\/health$/.exec(path);
  const checkMatch = /^\/v1\/app\/workspaces\/([^/]+)\/gateways\/([^/]+)\/health\/check$/.exec(path);
  const match = checkMatch || detailsMatch;
  if (!match) return null;

  try {
    const user = await requestUser(request, env);
    if (!user) return errorResponse(401, "unauthorized", "Sign in is required");

    const workspaceId = decodeURIComponent(match[1]);
    const gatewayId = decodeURIComponent(match[2]);
    const membership = await getWorkspaceMembership(env.DB, workspaceId, user.id);
    if (!membership) return errorResponse(404, "workspace_not_found", "Workspace not found");

    const gateway = await loadGatewayHealthTarget(env.DB, gatewayId, membership.account_id);
    if (!gateway) return errorResponse(404, "gateway_not_found", "Gateway not found");

    if (detailsMatch && request.method === "GET") {
      const row = await env.DB
        .prepare(
          `SELECT id, health_status, health_reason, last_health_checked_at, last_health_success_at,
                  last_health_failure_at, last_health_latency_ms, last_health_http_status,
                  consecutive_health_failures, connection_mode
           FROM gateways
           WHERE id = ? AND account_id = ?`,
        )
        .bind(gatewayId, membership.account_id)
        .first<Record<string, unknown>>();
      return json({
        gateway: row,
        history: await listGatewayHealthHistory(env.DB, gatewayId, membership.account_id, 24),
      });
    }

    if (checkMatch && request.method === "POST") {
      if (membership.role !== "owner" && membership.role !== "admin") {
        return errorResponse(403, "forbidden", "Owner or admin role is required to run gateway diagnostics");
      }
      const result = await runGatewayHealthCheck(env, gateway, {
        triggerType: "manual",
        actorUserId: user.id,
        workspaceId,
      });
      return json({ result });
    }

    return errorResponse(405, "method_not_allowed", "Method not allowed for gateway health route");
  } catch (error) {
    return errorResponse(400, "invalid_request", error instanceof Error ? error.message : "Invalid request");
  }
}
