import { useEffect, useState } from "react";
import { api } from "./api";

type InvitationPreview = {
  invitation: {
    workspaceId: string;
    workspaceName: string;
    email: string;
    role: "admin" | "member";
    expiresAt: string;
  };
};

function utcDate(value: string): Date {
  if (value.endsWith("Z")) return new Date(value);
  return new Date(`${value.replace(" ", "T")}Z`);
}

export function InviteAcceptance({ token, onAccepted, onCancel }: { token: string; onAccepted: () => Promise<void>; onCancel: () => void }) {
  const [preview, setPreview] = useState<InvitationPreview | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setError("");
    void api<InvitationPreview>(`/v1/app/invitations/${encodeURIComponent(token)}`)
      .then(setPreview)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "Could not load invitation"));
  }, [token]);

  async function accept() {
    setBusy(true); setError("");
    try {
      await api(`/v1/app/invitations/${encodeURIComponent(token)}/accept`, { method: "POST" });
      const url = new URL(window.location.href);
      url.searchParams.delete("invite");
      window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
      await onAccepted();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not accept invitation");
    } finally { setBusy(false); }
  }

  return <main className="auth-shell">
    <section className="auth-copy"><div className="brand-mark">CG</div><p className="eyebrow">CONTEXTGATEWAY INVITATION</p><h1>Join a secured MCP workspace.</h1><p className="lede">The invitation is email-bound, expires after seven days, and grants only the workspace role shown here.</p></section>
    <section className="auth-card">
      <h2>{preview ? `Join ${preview.invitation.workspaceName}` : "Loading invitation…"}</h2>
      {preview && <><p>Signed-in email: <strong>{preview.invitation.email}</strong></p><p>Role: <span className="badge good">{preview.invitation.role}</span></p><p className="fine-print">Expires {utcDate(preview.invitation.expiresAt).toLocaleString()}.</p></>}
      {error && <div className="error-banner">{error}</div>}
      <div className="card-actions"><button onClick={onCancel}>Cancel</button><button className="primary" disabled={!preview || busy} onClick={accept}>{busy ? "Joining…" : "Accept invitation"}</button></div>
    </section>
  </main>;
}
