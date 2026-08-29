export type WorkspaceRole = "owner" | "admin" | "member";
export type InvitableWorkspaceRole = "admin" | "member";

export function normalizeInviteEmail(value: unknown): string {
  if (typeof value !== "string") throw new Error("email must be a string");
  const email = value.trim().toLowerCase();
  if (!email || email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error("email must be a valid email address");
  }
  return email;
}

export function parseInvitableRole(value: unknown): InvitableWorkspaceRole {
  if (value === undefined || value === null || value === "member") return "member";
  if (value === "admin") return "admin";
  throw new Error("role must be admin or member");
}

export function canInviteRole(actorRole: WorkspaceRole, targetRole: InvitableWorkspaceRole): boolean {
  if (actorRole === "owner") return true;
  return actorRole === "admin" && targetRole === "member";
}

export function canRevokeInvite(actorRole: WorkspaceRole, inviteRole: InvitableWorkspaceRole): boolean {
  return canInviteRole(actorRole, inviteRole);
}

export function canChangeMemberRole(
  actorRole: WorkspaceRole,
  currentRole: WorkspaceRole,
  targetRole: InvitableWorkspaceRole,
): boolean {
  if (actorRole !== "owner") return false;
  if (currentRole === "owner") return false;
  return currentRole !== targetRole;
}

export function canRemoveMember(actorRole: WorkspaceRole, targetRole: WorkspaceRole, sameUser: boolean): boolean {
  if (sameUser || targetRole === "owner") return false;
  if (actorRole === "owner") return true;
  return actorRole === "admin" && targetRole === "member";
}

export function seatUsage(memberCount: number, pendingInviteCount: number, limit: number) {
  const used = Math.max(0, memberCount);
  const reserved = Math.max(0, pendingInviteCount);
  const normalizedLimit = Math.max(0, limit);
  return {
    used,
    reserved,
    limit: normalizedLimit,
    available: Math.max(0, normalizedLimit - used - reserved),
    full: used + reserved >= normalizedLimit,
  };
}
