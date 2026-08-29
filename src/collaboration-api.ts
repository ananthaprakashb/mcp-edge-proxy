import { createAuth } from "./auth";
import {
  canChangeMemberRole,
  canInviteRole,
  canRemoveMember,
  canRevokeInvite,
  normalizeInviteEmail,
  parseInvitableRole,
  seatUsage,
  type InvitableWorkspaceRole,
  type WorkspaceRole,
} from "./collaboration";
import { sha256Hex } from "./crypto";
import { getPlanEntitlements } from "./entitlements";
import type { Env, Plan } from "./types";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

interface SessionUser {
  id: string;
  email: string;
  name: string;
}

interface MembershipContext {
  workspace_id: string;
  workspace_name: string;
  account_id: string;
  role: WorkspaceRole;
  plan: Plan;
}

interface InviteRow {
  id: string;
  workspace_id: string;
  workspace_name: string;
  email: string;
  role: InvitableWorkspaceRole;
  status: "pending" | "accepted" | "revoked" | "expired";
  expires_at: string;
  created_at: string;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function errorResponse(status: number, code: string, message: string): Response {
  return json({ error: { code, message } }, status);
}

async function readJsonObject(request: Request): Promise<Record<string, unknown>> {
  const body = (await request.json()) as unknown;
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("JSON request body must be an object");
  }
  return body as Record<string, unknown>;
}

function requiredInviteToken(body: Record<string, unknown>): string {
  const value = body.token;
  if (typeof value !== "string" || !/^cginv_[A-Za-z0-9_-]{40,}$/.test(value)) {
    throw new Error("A valid invitation token is required");
  }
  return value;
}

async function sessionUser(request: Request, env: Env): Promise<SessionUser | null> {
  const auth = createAuth(env, request);
  const session = await auth.api.getSession({ headers: request.headers });
  if (!session?.user) return null;
  return { id: session.user.id, email: session.user.email, name: session.user.name };
}

async function getMembership(env: Env, workspaceId: string, userId: string): Promise<MembershipContext | null> {
  return env.DB
    .prepare(
      `SELECT w.id AS workspace_id, w.name AS workspace_name, w.account_id,
              m.role, a.plan
       FROM workspace_members m
       JOIN workspaces w ON w.id = m.workspace_id
       JOIN accounts a ON a.id = w.account_id
       WHERE w.id = ? AND m.user_id = ?`,
    )
    .bind(workspaceId, userId)
    .first<MembershipContext>();
}

async function expireInvites(env: Env, workspaceId?: string): Promise<void> {
  if (workspaceId) {
    await env.DB
      .prepare(
        `UPDATE workspace_invites
         SET status = 'expired', updated_at = datetime('now')
         WHERE workspace_id = ? AND status = 'pending' AND datetime(expires_at) <= datetime('now')`,
      )
      .bind(workspaceId)
      .run();
    return;
  }
  await env.DB
    .prepare(
      `UPDATE workspace_invites
       SET status = 'expired', updated_at = datetime('now')
       WHERE status = 'pending' AND datetime(expires_at) <= datetime('now')`,
    )
    .run();
}

async function workspaceSeatUsage(env: Env, membership: MembershipContext) {
  const members = await env.DB
    .prepare(`SELECT COUNT(*) AS count FROM workspace_members WHERE workspace_id = ?`)
    .bind(membership.workspace_id)
    .first<{ count: number }>();
  const pending = await env.DB
    .prepare(
      `SELECT COUNT(*) AS count
       FROM workspace_invites
       WHERE workspace_id = ? AND status = 'pending' AND datetime(expires_at) > datetime('now')`,
    )
    .bind(membership.workspace_id)
    .first<{ count: number }>();
  return seatUsage(
    Number(members?.count ?? 0),
    Number(pending?.count ?? 0),
    getPlanEntitlements(membership.plan).memberLimit,
  );
}

function randomInviteToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const encoded = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return `cginv_${encoded}`;
}

async function lookupInviteByToken(env: Env, token: string): Promise<InviteRow | null> {
  return env.DB
    .prepare(
      `SELECT i.id, i.workspace_id, w.name AS workspace_name, i.email, i.role,
              i.status, i.expires_at, i.created_at
       FROM workspace_invites i
       JOIN workspaces w ON w.id = i.workspace_id
       WHERE i.token_hash = ?`,
    )
    .bind(await sha256Hex(token))
    .first<InviteRow>();
}

function inviteExpired(invite: InviteRow): boolean {
  const normalized = invite.expires_at.includes("T") ? invite.expires_at : invite.expires_at.replace(" ", "T");
  const expires = Date.parse(normalized.endsWith("Z") ? normalized : `${normalized}Z`);
  return Number.isFinite(expires) && expires <= Date.now();
}

async function inviteForUser(env: Env, token: string, user: SessionUser): Promise<InviteRow | Response> {
  const invite = await lookupInviteByToken(env, token);
  if (!invite) return errorResponse(404, "invite_not_found", "Invitation not found");
  if (invite.status !== "pending") {
    return errorResponse(409, `invite_${invite.status}`, `Invitation is ${invite.status}`);
  }
  if (inviteExpired(invite)) {
    await env.DB
      .prepare(`UPDATE workspace_invites SET status = 'expired', updated_at = datetime('now') WHERE id = ? AND status = 'pending'`)
      .bind(invite.id)
      .run();
    return errorResponse(410, "invite_expired", "Invitation has expired");
  }
  if (invite.email.toLowerCase() !== user.email.trim().toLowerCase()) {
    return errorResponse(403, "invite_email_mismatch", "Sign in with the email address that received this invitation");
  }
  return invite;
}

export async function handleCollaborationApi(request: Request, env: Env, path: string): Promise<Response | null> {
  const membersMatch = /^\/v1\/app\/workspaces\/([^/]+)\/members$/.exec(path);
  const memberMatch = /^\/v1\/app\/workspaces\/([^/]+)\/members\/([^/]+)$/.exec(path);
  const invitesMatch = /^\/v1\/app\/workspaces\/([^/]+)\/invites$/.exec(path);
  const inviteMatch = /^\/v1\/app\/workspaces\/([^/]+)\/invites\/([^/]+)$/.exec(path);
  const invitationPreview = path === "/v1/app/invitations/preview";
  const invitationAccept = path === "/v1/app/invitations/accept";

  if (!membersMatch && !memberMatch && !invitesMatch && !inviteMatch && !invitationPreview && !invitationAccept) return null;

  try {
    const user = await sessionUser(request, env);
    if (!user) return errorResponse(401, "unauthorized", "Sign in is required");

    if (invitationPreview && request.method === "POST") {
      const body = await readJsonObject(request);
      const invite = await inviteForUser(env, requiredInviteToken(body), user);
      if (invite instanceof Response) return invite;
      return json({
        invitation: {
          workspaceId: invite.workspace_id,
          workspaceName: invite.workspace_name,
          email: invite.email,
          role: invite.role,
          expiresAt: invite.expires_at,
        },
      });
    }

    if (invitationAccept && request.method === "POST") {
      const body = await readJsonObject(request);
      const invite = await inviteForUser(env, requiredInviteToken(body), user);
      if (invite instanceof Response) return invite;

      const existing = await getMembership(env, invite.workspace_id, user.id);
      if (existing) {
        await env.DB
          .prepare(
            `UPDATE workspace_invites
             SET status = 'accepted', accepted_by_user_id = ?, accepted_at = datetime('now'), updated_at = datetime('now')
             WHERE id = ? AND status = 'pending'`,
          )
          .bind(user.id, invite.id)
          .run();
        return json({ workspaceId: invite.workspace_id, workspaceName: invite.workspace_name, role: existing.role, alreadyMember: true });
      }

      const workspace = await env.DB
        .prepare(
          `SELECT w.id AS workspace_id, w.name AS workspace_name, w.account_id, 'member' AS role, a.plan
           FROM workspaces w JOIN accounts a ON a.id = w.account_id WHERE w.id = ?`,
        )
        .bind(invite.workspace_id)
        .first<MembershipContext>();
      if (!workspace) return errorResponse(404, "workspace_not_found", "Workspace not found");

      await expireInvites(env, invite.workspace_id);
      const seats = await workspaceSeatUsage(env, workspace);
      if (seats.used >= seats.limit) {
        return errorResponse(409, "plan_limit_reached", `${getPlanEntitlements(workspace.plan).displayName} allows ${seats.limit} workspace member${seats.limit === 1 ? "" : "s"}`);
      }

      try {
        await env.DB.batch([
          env.DB
            .prepare(`INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, ?)`)
            .bind(invite.workspace_id, user.id, invite.role),
          env.DB
            .prepare(
              `UPDATE workspace_invites
               SET status = 'accepted', accepted_by_user_id = ?, accepted_at = datetime('now'), updated_at = datetime('now')
               WHERE id = ? AND status = 'pending'`,
            )
            .bind(user.id, invite.id),
        ]);
      } catch (error) {
        if (error instanceof Error && error.message.includes("workspace_member_plan_limit")) {
          return errorResponse(409, "plan_limit_reached", "The workspace member limit was reached before this invitation could be accepted");
        }
        throw error;
      }

      return json({ workspaceId: invite.workspace_id, workspaceName: invite.workspace_name, role: invite.role }, 201);
    }

    const workspaceId = decodeURIComponent((membersMatch || memberMatch || invitesMatch || inviteMatch)![1]);
    const membership = await getMembership(env, workspaceId, user.id);
    if (!membership) return errorResponse(404, "workspace_not_found", "Workspace not found");

    await expireInvites(env, workspaceId);

    if (membersMatch && request.method === "GET") {
      const members = await env.DB
        .prepare(
          `SELECT m.user_id, u.name, u.email, u.image, m.role, m.created_at
           FROM workspace_members m
           JOIN "user" u ON u.id = m.user_id
           WHERE m.workspace_id = ?
           ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, m.created_at ASC`,
        )
        .bind(workspaceId)
        .all<Record<string, unknown>>();

      let invites: Record<string, unknown>[] = [];
      if (membership.role === "owner" || membership.role === "admin") {
        const result = await env.DB
          .prepare(
            `SELECT i.id, i.email, i.role, i.status, i.expires_at, i.created_at,
                    inviter.name AS invited_by_name, inviter.email AS invited_by_email
             FROM workspace_invites i
             LEFT JOIN "user" inviter ON inviter.id = i.invited_by_user_id
             WHERE i.workspace_id = ? AND i.status = 'pending'
             ORDER BY i.created_at DESC`,
          )
          .bind(workspaceId)
          .all<Record<string, unknown>>();
        invites = result.results ?? [];
      }

      return json({
        workspace: { id: membership.workspace_id, name: membership.workspace_name, role: membership.role, plan: membership.plan },
        members: members.results ?? [],
        invites,
        seats: await workspaceSeatUsage(env, membership),
      });
    }

    if (invitesMatch && request.method === "POST") {
      if (membership.role !== "owner" && membership.role !== "admin") {
        return errorResponse(403, "forbidden", "Owner or admin role is required to invite members");
      }
      const body = await readJsonObject(request);
      const email = normalizeInviteEmail(body.email);
      const role = parseInvitableRole(body.role);
      if (!canInviteRole(membership.role, role)) {
        return errorResponse(403, "forbidden", "Admins may invite members only; only owners may invite admins");
      }

      const existingMember = await env.DB
        .prepare(
          `SELECT m.user_id FROM workspace_members m
           JOIN "user" u ON u.id = m.user_id
           WHERE m.workspace_id = ? AND lower(u.email) = ?`,
        )
        .bind(workspaceId, email)
        .first<{ user_id: string }>();
      if (existingMember) return errorResponse(409, "already_member", "That email already belongs to a workspace member");

      const pendingInvite = await env.DB
        .prepare(`SELECT id FROM workspace_invites WHERE workspace_id = ? AND email = ? AND status = 'pending'`)
        .bind(workspaceId, email)
        .first<{ id: string }>();
      if (pendingInvite) return errorResponse(409, "invite_exists", "A pending invitation already exists for that email");

      const seats = await workspaceSeatUsage(env, membership);
      if (seats.full) {
        const entitlement = getPlanEntitlements(membership.plan);
        return errorResponse(409, "plan_limit_reached", `${entitlement.displayName} allows ${entitlement.memberLimit} workspace member${entitlement.memberLimit === 1 ? "" : "s"}, including pending invitations`);
      }

      const token = randomInviteToken();
      const id = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + INVITE_TTL_MS).toISOString();
      await env.DB
        .prepare(
          `INSERT INTO workspace_invites
             (id, workspace_id, email, role, token_hash, invited_by_user_id, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(id, workspaceId, email, role, await sha256Hex(token), user.id, expiresAt)
        .run();

      const origin = new URL(request.url).origin;
      return json(
        {
          invitation: {
            id,
            email,
            role,
            status: "pending",
            expiresAt,
            inviteUrl: `${origin}/#invite=${encodeURIComponent(token)}`,
          },
          seats: await workspaceSeatUsage(env, membership),
          warning: "The invite URL is returned only at creation time; ContextGateway stores only its SHA-256 token hash.",
        },
        201,
      );
    }

    if (inviteMatch && request.method === "DELETE") {
      if (membership.role !== "owner" && membership.role !== "admin") {
        return errorResponse(403, "forbidden", "Owner or admin role is required to revoke invitations");
      }
      const inviteId = decodeURIComponent(inviteMatch[2]);
      const invite = await env.DB
        .prepare(`SELECT id, role FROM workspace_invites WHERE id = ? AND workspace_id = ? AND status = 'pending'`)
        .bind(inviteId, workspaceId)
        .first<{ id: string; role: InvitableWorkspaceRole }>();
      if (!invite) return errorResponse(404, "invite_not_found", "Pending invitation not found");
      if (!canRevokeInvite(membership.role, invite.role)) {
        return errorResponse(403, "forbidden", "Admins cannot revoke admin invitations");
      }
      await env.DB
        .prepare(
          `UPDATE workspace_invites
           SET status = 'revoked', revoked_at = datetime('now'), updated_at = datetime('now')
           WHERE id = ? AND workspace_id = ? AND status = 'pending'`,
        )
        .bind(inviteId, workspaceId)
        .run();
      return new Response(null, { status: 204 });
    }

    if (memberMatch && request.method === "PATCH") {
      if (membership.role !== "owner") return errorResponse(403, "forbidden", "Only the workspace owner can change member roles");
      const targetUserId = decodeURIComponent(memberMatch[2]);
      const target = await env.DB
        .prepare(`SELECT user_id, role FROM workspace_members WHERE workspace_id = ? AND user_id = ?`)
        .bind(workspaceId, targetUserId)
        .first<{ user_id: string; role: WorkspaceRole }>();
      if (!target) return errorResponse(404, "member_not_found", "Workspace member not found");
      const body = await readJsonObject(request);
      const targetRole = parseInvitableRole(body.role);
      if (!canChangeMemberRole(membership.role, target.role, targetRole)) {
        return errorResponse(409, "role_change_not_allowed", target.role === "owner" ? "Owner transfer is not supported in this phase" : "Member already has that role");
      }
      await env.DB
        .prepare(`UPDATE workspace_members SET role = ? WHERE workspace_id = ? AND user_id = ?`)
        .bind(targetRole, workspaceId, targetUserId)
        .run();
      return json({ userId: targetUserId, role: targetRole });
    }

    if (memberMatch && request.method === "DELETE") {
      const targetUserId = decodeURIComponent(memberMatch[2]);
      const target = await env.DB
        .prepare(`SELECT user_id, role FROM workspace_members WHERE workspace_id = ? AND user_id = ?`)
        .bind(workspaceId, targetUserId)
        .first<{ user_id: string; role: WorkspaceRole }>();
      if (!target) return errorResponse(404, "member_not_found", "Workspace member not found");
      if (!canRemoveMember(membership.role, target.role, targetUserId === user.id)) {
        return errorResponse(403, "member_remove_not_allowed", "You cannot remove this workspace member");
      }
      await env.DB
        .prepare(`DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?`)
        .bind(workspaceId, targetUserId)
        .run();
      return new Response(null, { status: 204 });
    }

    return errorResponse(405, "method_not_allowed", "Method not allowed for collaboration route");
  } catch (error) {
    return errorResponse(400, "invalid_request", error instanceof Error ? error.message : "Invalid request");
  }
}
