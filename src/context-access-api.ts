import { getWorkspaceMembership } from "./app-db";
import { createAuth } from "./auth";
import { listContextDocumentAccess } from "./context-access-db";
import { normalizeDocumentKey } from "./context-document";
import type { Env } from "./types";

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

export async function handleContextAccessApi(request: Request, env: Env, path: string): Promise<Response | null> {
  const match = /^\/v1\/app\/workspaces\/([^/]+)\/documents\/([^/]+)\/access$/.exec(path);
  if (!match) return null;
  if (request.method !== "GET") return json({ error: { code: "method_not_allowed", message: "GET required" } }, 405);

  const session = await createAuth(env, request).api.getSession({ headers: request.headers });
  if (!session?.user) return json({ error: { code: "unauthorized", message: "Sign in is required" } }, 401);
  const workspaceId = decodeURIComponent(match[1]);
  const membership = await getWorkspaceMembership(env.DB, workspaceId, session.user.id);
  if (!membership) return json({ error: { code: "workspace_not_found", message: "Workspace not found" } }, 404);

  try {
    const documentKey = normalizeDocumentKey(decodeURIComponent(match[2]));
    const url = new URL(request.url);
    const limit = Math.max(1, Math.min(250, Math.floor(Number(url.searchParams.get("limit") ?? "100")) || 100));
    return json({ access: await listContextDocumentAccess(env.DB, membership.account_id, documentKey, limit) });
  } catch (error) {
    return json({ error: { code: "invalid_request", message: error instanceof Error ? error.message : "Invalid request" } }, 400);
  }
}
