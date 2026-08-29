import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { api } from "./api";

type WorkspaceRole = "owner" | "admin" | "member";
type InvitableRole = "admin" | "member";

type Member = {
  user_id: string;
  name: string;
  email: string;
  image?: string | null;
  role: WorkspaceRole;
  created_at: string;
};

type Invite = {
  id: string;
  email: string;
  role: InvitableRole;
  status: "pending";
  expires_at: string;
  created_at: string;
  invited_by_name?: string | null;
};

type TeamData = {
  workspace: { id: string; name: string; role: WorkspaceRole; plan: "free" | "pro" | "team" };
  members: Member[];
  invites: Invite[];
  seats: { used: number; reserved: number; limit: number; available: number; full: boolean };
};

type Props = {
  workspace: { id: string; role: WorkspaceRole; plan: "free" | "pro" | "team" };
};

function utcDate(value: string): Date {
  if (value.endsWith("Z")) return new Date(value);
  return new Date(`${value.replace(" ", "T")}Z`);
}

export function TeamPanel({ workspace }: Props) {
  const [data, setData] = useState<TeamData | null>(null);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<InvitableRole>("member");
  const [inviteUrl, setInviteUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    setData(await api<TeamData>(`/v1/app/workspaces/${workspace.id}/members`));
  }, [workspace.id]);

  useEffect(() => {
    setInviteUrl("");
    void load().catch((e: unknown) => setError(e instanceof Error ? e.message : "Could not load workspace members"));
  }, [load]);

  async function invite(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError(""); setNotice(""); setInviteUrl("");
    try {
      const result = await api<{ invitation: { inviteUrl: string; email: string; role: InvitableRole } }>(`/v1/app/workspaces/${workspace.id}/invites`, {
        method: "POST",
        body: JSON.stringify({ email, role }),
      });
      setInviteUrl(result.invitation.inviteUrl);
      setNotice(`Invitation created for ${result.invitation.email}. Copy the link now; the token is not stored in plaintext.`);
      setEmail("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create invitation");
    } finally { setBusy(false); }
  }

  async function copyInvite() {
    if (!inviteUrl) return;
    await navigator.clipboard.writeText(inviteUrl);
    setNotice("Invitation link copied.");
  }

  async function revokeInvite(inviteId: string) {
    if (!confirm("Revoke this pending invitation? The link will stop working immediately.")) return;
    setError("");
    try {
      await api(`/v1/app/workspaces/${workspace.id}/invites/${inviteId}`, { method: "DELETE" });
      setNotice("Invitation revoked.");
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not revoke invitation"); }
  }

  async function changeRole(userId: string, nextRole: InvitableRole) {
    setError("");
    try {
      await api(`/v1/app/workspaces/${workspace.id}/members/${userId}`, {
        method: "PATCH",
        body: JSON.stringify({ role: nextRole }),
      });
      setNotice("Member role updated.");
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not update member role"); }
  }

  async function removeMember(userId: string, name: string) {
    if (!confirm(`Remove ${name} from this workspace? Their dashboard access will stop immediately.`)) return;
    setError("");
    try {
      await api(`/v1/app/workspaces/${workspace.id}/members/${userId}`, { method: "DELETE" });
      setNotice("Member removed.");
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not remove member"); }
  }

  if (!data) return <div className="panel loading-panel">Loading workspace members…</div>;
  const manager = workspace.role === "owner" || workspace.role === "admin";

  return <section className="stack-lg">
    {error && <div className="error-banner">{error}<button onClick={() => setError("")}>×</button></div>}
    {notice && <div className="success-banner">{notice}<button onClick={() => setNotice("")}>×</button></div>}
    <div className="metrics metrics-four">
      <div className="metric-card"><span>Members</span><strong>{data.seats.used}</strong><small>Active workspace users</small></div>
      <div className="metric-card"><span>Pending</span><strong>{data.seats.reserved}</strong><small>Reserved invitation seats</small></div>
      <div className="metric-card"><span>Seat limit</span><strong>{data.seats.limit}</strong><small>{data.workspace.plan.toUpperCase()} plan</small></div>
      <div className="metric-card"><span>Available</span><strong>{data.seats.available}</strong><small>Seats remaining</small></div>
    </div>

    {manager && <div className="panel">
      <div className="panel-head"><div><span className="kicker">COLLABORATION</span><h3>Invite teammate</h3><p>Links expire after 7 days, are bound to the invited email address, and reserve a plan seat while pending.</p></div></div>
      <div className="panel-body">
        {data.seats.full ? <div className="error-banner">Your {data.workspace.plan.toUpperCase()} plan has no available team seats. Revoke a pending invite, remove a member, or upgrade the plan.</div> :
          <form className="inline-form" onSubmit={invite}>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="teammate@example.com" required />
            <select value={role} onChange={(e) => setRole(e.target.value as InvitableRole)}>
              <option value="member">Member</option>
              {workspace.role === "owner" && <option value="admin">Admin</option>}
            </select>
            <button className="primary" disabled={busy}>{busy ? "Creating…" : "Create invite"}</button>
          </form>}
        {inviteUrl && <div className="secret-box"><div><span className="kicker">ONE-TIME INVITE LINK</span><code>{inviteUrl}</code></div><button onClick={copyInvite}>Copy link</button></div>}
      </div>
    </div>}

    <div className="panel">
      <div className="panel-head"><div><span className="kicker">ACCESS</span><h3>Workspace members</h3><p>Owners control billing and roles. Admins manage gateways, keys, and member invitations. Members have read-only access.</p></div><button onClick={() => load()}>Refresh</button></div>
      <div className="table-wrap"><table><thead><tr><th>Member</th><th>Role</th><th>Joined</th><th>Actions</th></tr></thead><tbody>{data.members.map((member) => <tr key={member.user_id}>
        <td><strong>{member.name}</strong><small>{member.email}</small></td>
        <td>{workspace.role === "owner" && member.role !== "owner" ? <select value={member.role} onChange={(e) => void changeRole(member.user_id, e.target.value as InvitableRole)}><option value="member">Member</option><option value="admin">Admin</option></select> : <span className={`badge ${member.role === "owner" ? "good" : member.role === "admin" ? "warn" : ""}`}>{member.role}</span>}</td>
        <td>{utcDate(member.created_at).toLocaleDateString()}</td>
        <td>{member.role !== "owner" && ((workspace.role === "owner") || (workspace.role === "admin" && member.role === "member")) ? <button className="danger-link" onClick={() => removeMember(member.user_id, member.name)}>Remove</button> : "—"}</td>
      </tr>)}</tbody></table></div>
    </div>

    {manager && <div className="panel">
      <div className="panel-head"><div><span className="kicker">PENDING ACCESS</span><h3>Invitations</h3><p>Revoke and recreate an invitation if the one-time link is lost.</p></div></div>
      {!data.invites.length ? <div className="table-empty"><strong>No pending invitations</strong><span>Your workspace has no reserved invite seats.</span></div> : <div className="table-wrap"><table><thead><tr><th>Email</th><th>Role</th><th>Invited by</th><th>Expires</th><th>Action</th></tr></thead><tbody>{data.invites.map((invite) => <tr key={invite.id}>
        <td><strong>{invite.email}</strong></td><td><span className="badge">{invite.role}</span></td><td>{invite.invited_by_name || "—"}</td><td>{utcDate(invite.expires_at).toLocaleString()}</td><td>{workspace.role === "owner" || invite.role === "member" ? <button className="danger-link" onClick={() => revokeInvite(invite.id)}>Revoke</button> : "—"}</td>
      </tr>)}</tbody></table></div>}
    </div>}
  </section>;
}
