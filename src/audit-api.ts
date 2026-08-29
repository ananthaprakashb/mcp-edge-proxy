import { ensureAuditChainBackfilled, verifyAuditChain } from "./audit-db";
import { getWorkspaceMembership } from "./app-db";
import { createAuth } from "./auth";
import { getRetentionSummary, runRetentionLifecycle } from "./retention";
import type { D1Database, Env } from "./types";

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

function csvCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  const text = String(value);
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function auditEventsCsv(events: Record<string, unknown>[]): string {
  const fields = [
    "id",
    "event_type",
    "actor_name",
    "actor_email",
    "target_type",
    "target_id",
    "metadata_json",
    "chain_sequence",
    "previous_hash",
    "event_hash",
    "created_at",
  ];
  return [
    fields.join(","),
    ...events.map((event) => fields.map((field) => csvCell(event[field])).join(",")),
  ].join("\n");
}

function parseLimit(value: string | null, fallback: number, maximum: number): number {
  const parsed = Number(value ?? fallback);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(1, Math.min(maximum, Math.floor(parsed)));
}

async function listAuditEvents(
  db: D1Database,
  accountId: string,
  url: URL,
  maximum: number,
): Promise<Record<string, unknown>[]> {
  await ensureAuditChainBackfilled(db, accountId);
  const conditions = ["e.account_id = ?"];
  const values: unknown[] = [accountId];
  const eventType = url.searchParams.get("eventType");
  const targetType = url.searchParams.get("targetType");
  const actorUserId = url.searchParams.get("actorUserId");
  const from = url.searchParams.get("from");
  const to = url.searchParams.get("to");
  if (eventType) { conditions.push("e.event_type = ?"); values.push(eventType); }
  if (targetType) { conditions.push("e.target_type = ?"); values.push(targetType); }
  if (actorUserId) { conditions.push("e.actor_user_id = ?"); values.push(actorUserId); }
  if (from) { conditions.push("datetime(e.created_at) >= datetime(?)"); values.push(from); }
  if (to) { conditions.push("datetime(e.created_at) <= datetime(?)"); values.push(to); }
  const limit = parseLimit(url.searchParams.get("limit"), Math.min(100, maximum), maximum);
  values.push(limit);

  const result = await db
    .prepare(
      `SELECT e.id, e.event_type, e.target_type, e.target_id, e.metadata_json, e.created_at,
              e.chain_sequence, e.previous_hash, e.event_hash,
              e.actor_user_id, u.name AS actor_name, u.email AS actor_email
       FROM security_events e
       LEFT JOIN "user" u ON u.id = e.actor_user_id
       WHERE ${conditions.join(" AND ")}
       ORDER BY datetime(e.created_at) DESC, e.id DESC
       LIMIT ?`,
    )
    .bind(...values)
    .all<Record<string, unknown>>();
  return result.results ?? [];
}

async function requestUser(request: Request, env: Env) {
  const session = await createAuth(env, request).api.getSession({ headers: request.headers });
  return session?.user ?? null;
}

export async function handleAuditApi(request: Request, env: Env, path: string): Promise<Response | null> {
  const auditMatch = /^\/v1\/app\/workspaces\/([^/]+)\/audit$/.exec(path);
  const exportMatch = /^\/v1\/app\/workspaces\/([^/]+)\/audit\/export$/.exec(path);
  const verifyMatch = /^\/v1\/app\/workspaces\/([^/]+)\/audit\/verify$/.exec(path);
  const retentionMatch = /^\/v1\/app\/workspaces\/([^/]+)\/retention$/.exec(path);
  const retentionRunMatch = /^\/v1\/app\/workspaces\/([^/]+)\/retention\/run$/.exec(path);
  const match = auditMatch || exportMatch || verifyMatch || retentionMatch || retentionRunMatch;
  if (!match) return null;

  try {
    const user = await requestUser(request, env);
    if (!user) return errorResponse(401, "unauthorized", "Sign in is required");
    const workspaceId = decodeURIComponent(match[1]);
    const membership = await getWorkspaceMembership(env.DB, workspaceId, user.id);
    if (!membership) return errorResponse(404, "workspace_not_found", "Workspace not found");
    const manager = membership.role === "owner" || membership.role === "admin";

    if (auditMatch && request.method === "GET") {
      const url = new URL(request.url);
      return json({ events: await listAuditEvents(env.DB, membership.account_id, url, 500) });
    }

    if (exportMatch && request.method === "GET") {
      if (!manager) return errorResponse(403, "forbidden", "Owner or admin role is required to export audit history");
      const url = new URL(request.url);
      const events = await listAuditEvents(env.DB, membership.account_id, url, 5000);
      const format = url.searchParams.get("format") ?? "csv";
      if (format === "json") {
        return new Response(JSON.stringify({ workspace: membership.name, exportedAt: new Date().toISOString(), events }, null, 2), {
          headers: {
            "content-type": "application/json; charset=utf-8",
            "content-disposition": `attachment; filename="contextgateway-audit-${workspaceId}.json"`,
            "cache-control": "no-store",
          },
        });
      }
      if (format !== "csv") return errorResponse(400, "invalid_format", "format must be csv or json");
      return new Response(auditEventsCsv(events), {
        headers: {
          "content-type": "text/csv; charset=utf-8",
          "content-disposition": `attachment; filename="contextgateway-audit-${workspaceId}.csv"`,
          "cache-control": "no-store",
        },
      });
    }

    if (verifyMatch && request.method === "GET") {
      return json({ integrity: await verifyAuditChain(env.DB, membership.account_id) });
    }

    if (retentionMatch && request.method === "GET") {
      return json({ retention: await getRetentionSummary(env.DB, membership.account_id, membership.plan) });
    }

    if (retentionRunMatch && request.method === "POST") {
      if (!manager) return errorResponse(403, "forbidden", "Owner or admin role is required to run retention cleanup");
      const runs = await runRetentionLifecycle(env.DB, {
        triggerType: "manual",
        accountId: membership.account_id,
        requestedByUserId: user.id,
      });
      const run = runs[0];
      if (!run) return errorResponse(404, "account_not_found", "Workspace account not found");
      return json({ run }, run.status === "completed" ? 200 : 409);
    }

    return errorResponse(405, "method_not_allowed", "Method not allowed for audit or retention route");
  } catch (error) {
    return errorResponse(400, "invalid_request", error instanceof Error ? error.message : "Invalid request");
  }
}
