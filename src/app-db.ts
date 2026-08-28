import type { D1Database, Plan, SubscriptionStatus } from "./types";

export type WorkspaceRole = "owner" | "admin" | "member";

export interface WorkspaceMembership {
  id: string;
  account_id: string;
  name: string;
  slug: string;
  role: WorkspaceRole;
  plan: Plan;
  subscription_status: SubscriptionStatus;
}

export async function createWorkspace(
  db: D1Database,
  input: { id: string; accountId: string; userId: string; name: string; slug: string },
): Promise<void> {
  const accountInsert = db
    .prepare(`INSERT INTO accounts (id, name, plan, subscription_status) VALUES (?, ?, 'free', 'free')`)
    .bind(input.accountId, input.name);
  const workspaceInsert = db
    .prepare(
      `INSERT INTO workspaces (id, account_id, name, slug, created_by_user_id)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .bind(input.id, input.accountId, input.name, input.slug, input.userId);
  const memberInsert = db
    .prepare(`INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, 'owner')`)
    .bind(input.id, input.userId);

  await db.batch([accountInsert, workspaceInsert, memberInsert]);
}

export async function listWorkspacesForUser(db: D1Database, userId: string): Promise<WorkspaceMembership[]> {
  const result = await db
    .prepare(
      `SELECT w.id, w.account_id, w.name, w.slug, m.role, a.plan, a.subscription_status
       FROM workspace_members m
       JOIN workspaces w ON w.id = m.workspace_id
       JOIN accounts a ON a.id = w.account_id
       WHERE m.user_id = ?
       ORDER BY w.created_at ASC`,
    )
    .bind(userId)
    .all<WorkspaceMembership>();
  return result.results ?? [];
}

export async function getWorkspaceMembership(
  db: D1Database,
  workspaceId: string,
  userId: string,
): Promise<WorkspaceMembership | null> {
  return db
    .prepare(
      `SELECT w.id, w.account_id, w.name, w.slug, m.role, a.plan, a.subscription_status
       FROM workspace_members m
       JOIN workspaces w ON w.id = m.workspace_id
       JOIN accounts a ON a.id = w.account_id
       WHERE w.id = ? AND m.user_id = ?`,
    )
    .bind(workspaceId, userId)
    .first<WorkspaceMembership>();
}

export async function workspaceSlugExists(db: D1Database, slug: string): Promise<boolean> {
  const row = await db.prepare(`SELECT id FROM workspaces WHERE slug = ?`).bind(slug).first<{ id: string }>();
  return Boolean(row);
}

export async function listWorkspaceGateways(db: D1Database, accountId: string): Promise<Record<string, unknown>[]> {
  const result = await db
    .prepare(
      `SELECT g.id, g.name, g.upstream_url, g.enabled, g.created_at,
              COUNT(k.id) AS key_count,
              SUM(CASE WHEN k.revoked_at IS NULL THEN 1 ELSE 0 END) AS active_key_count
       FROM gateways g
       LEFT JOIN api_keys k ON k.gateway_id = g.id
       WHERE g.account_id = ?
       GROUP BY g.id
       ORDER BY g.created_at DESC`,
    )
    .bind(accountId)
    .all<Record<string, unknown>>();
  return result.results ?? [];
}

export async function listGatewayKeys(
  db: D1Database,
  accountId: string,
  gatewayId: string,
): Promise<Record<string, unknown>[]> {
  const result = await db
    .prepare(
      `SELECT id, name, key_prefix, allowed_methods, allowed_names, execution_mode, revoked_at, created_at
       FROM api_keys
       WHERE account_id = ? AND gateway_id = ?
       ORDER BY created_at DESC`,
    )
    .bind(accountId, gatewayId)
    .all<Record<string, unknown>>();
  return result.results ?? [];
}

export async function getWorkspaceOverview(db: D1Database, accountId: string): Promise<Record<string, number>> {
  const gateway = await db
    .prepare(`SELECT COUNT(*) AS count FROM gateways WHERE account_id = ? AND enabled = 1`)
    .bind(accountId)
    .first<{ count: number }>();
  const keys = await db
    .prepare(`SELECT COUNT(*) AS count FROM api_keys WHERE account_id = ? AND revoked_at IS NULL`)
    .bind(accountId)
    .first<{ count: number }>();
  const traces = await db
    .prepare(
      `SELECT COUNT(*) AS total,
              SUM(CASE WHEN decision IN (
                'policy_denied', 'capability_required', 'capability_scope_denied',
                'capability_arguments_denied', 'capability_replayed', 'capability_invalid',
                'capability_parent_invalid', 'unauthorized', 'operation_mismatch'
              ) THEN 1 ELSE 0 END) AS denied,
              COALESCE(ROUND(AVG(duration_ms)), 0) AS avg_latency
       FROM traces
       WHERE account_id = ? AND created_at >= datetime('now', '-24 hours')`,
    )
    .bind(accountId)
    .first<{ total: number; denied: number | null; avg_latency: number }>();

  return {
    gateways: Number(gateway?.count ?? 0),
    activeKeys: Number(keys?.count ?? 0),
    requests24h: Number(traces?.total ?? 0),
    denied24h: Number(traces?.denied ?? 0),
    avgLatencyMs: Number(traces?.avg_latency ?? 0),
  };
}

export async function listWorkspaceTraces(
  db: D1Database,
  accountId: string,
  options: { gatewayId?: string | null; decision?: string | null; authMode?: string | null; q?: string | null; limit: number },
): Promise<Record<string, unknown>[]> {
  const conditions = ["t.account_id = ?"];
  const values: unknown[] = [accountId];
  if (options.gatewayId) {
    conditions.push("t.gateway_id = ?");
    values.push(options.gatewayId);
  }
  if (options.decision) {
    conditions.push("t.decision = ?");
    values.push(options.decision);
  }
  if (options.authMode) {
    conditions.push("t.auth_mode = ?");
    values.push(options.authMode);
  }
  if (options.q) {
    conditions.push("(t.mcp_name LIKE ? OR t.mcp_method LIKE ? OR t.request_id LIKE ? OR t.policy_reason LIKE ? OR t.capability_jti LIKE ?)");
    const term = `%${options.q}%`;
    values.push(term, term, term, term, term);
  }
  values.push(options.limit);

  const result = await db
    .prepare(
      `SELECT t.id, t.request_id, t.gateway_id, g.name AS gateway_name, t.api_key_id,
              k.name AS key_name, k.execution_mode, t.mcp_method, t.mcp_name, t.decision,
              t.status_code, t.duration_ms, t.request_bytes, t.response_bytes, t.auth_mode,
              t.capability_jti, t.policy_reason, t.policy_method_rule, t.policy_name_rule,
              t.created_at
       FROM traces t
       JOIN gateways g ON g.id = t.gateway_id
       LEFT JOIN api_keys k ON k.id = t.api_key_id
       WHERE ${conditions.join(" AND ")}
       ORDER BY t.created_at DESC
       LIMIT ?`,
    )
    .bind(...values)
    .all<Record<string, unknown>>();
  return result.results ?? [];
}
