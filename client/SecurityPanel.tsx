import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { api } from "./api";

type WorkspaceRole = "owner" | "admin" | "member";
type ConnectionMode = "public" | "cloudflare_access";

type Gateway = {
  id: string;
  name: string;
  connection_mode: ConnectionMode;
  upstream_secret_version: number;
  credentials_rotated_at: string | null;
};

type AgentKey = {
  id: string;
  name: string;
  key_prefix: string;
  execution_mode: "direct" | "capability_required";
  revoked_at: string | null;
  secret_version: number;
  secret_rotated_at: string | null;
  previous_secret_valid_until: string | null;
};

type SecurityEvent = {
  id: string;
  event_type: string;
  target_type: string;
  target_id: string;
  metadata_json: string;
  created_at: string;
  actor_name: string | null;
  actor_email: string | null;
};

type SecuritySummary = {
  keyrings: {
    upstreamEncryption: { activeVersion: number; configuredVersions: number[] };
    capabilitySigning: { activeKid: string; configuredKids: string[] };
  };
  events: SecurityEvent[];
};

type Props = {
  workspace: { id: string; role: WorkspaceRole };
};

function utcDate(value: string | null): string {
  if (!value) return "Never";
  const normalized = value.includes("T") ? value : value.replace(" ", "T");
  return new Date(normalized.endsWith("Z") ? normalized : `${normalized}Z`).toLocaleString();
}

export function SecurityPanel({ workspace }: Props) {
  const [summary, setSummary] = useState<SecuritySummary | null>(null);
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [keys, setKeys] = useState<Record<string, AgentKey[]>>({});
  const [expandedGateway, setExpandedGateway] = useState<string | null>(null);
  const [newSecret, setNewSecret] = useState<{ value: string; version: number; previousValidUntil: string | null } | null>(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    const [security, gatewayData] = await Promise.all([
      api<SecuritySummary>(`/v1/app/workspaces/${workspace.id}/security`),
      api<{ gateways: Gateway[] }>(`/v1/app/workspaces/${workspace.id}/gateways`),
    ]);
    setSummary(security);
    setGateways(gatewayData.gateways);
  }, [workspace.id]);

  useEffect(() => { void load().catch((e: unknown) => setError(e instanceof Error ? e.message : "Could not load credential lifecycle")); }, [load]);

  async function loadKeys(gatewayId: string) {
    const data = await api<{ keys: AgentKey[] }>(`/v1/app/workspaces/${workspace.id}/gateways/${gatewayId}/keys`);
    setKeys((current) => ({ ...current, [gatewayId]: data.keys }));
    setExpandedGateway(gatewayId);
  }

  async function rotateKey(gatewayId: string, keyId: string, overlapSeconds: number) {
    setError(""); setNotice("");
    try {
      const result = await api<{ key: { key: string; version: number; previousValidUntil: string | null } }>(`/v1/app/workspaces/${workspace.id}/gateways/${gatewayId}/keys/${keyId}/rotate`, {
        method: "POST",
        body: JSON.stringify({ overlapSeconds }),
      });
      setNewSecret({ value: result.key.key, version: result.key.version, previousValidUntil: result.key.previousValidUntil });
      setNotice("Agent key rotated. Store the new plaintext key before closing it.");
      await Promise.all([loadKeys(gatewayId), load()]);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not rotate agent key"); }
  }

  if (!summary) return <div className="panel">Loading credential lifecycle…</div>;
  const manager = workspace.role === "owner" || workspace.role === "admin";

  return <section>
    <div className="panel">
      <div className="panel-head"><div><h3>Credential lifecycle</h3><p>Rotate upstream secrets and long-lived agent keys without recreating gateways. Secret values are never returned after creation/rotation.</p></div><button onClick={() => load()}>Refresh</button></div>
      {error && <div className="error-banner">{error}<button onClick={() => setError("")}>×</button></div>}
      {notice && <div className="success-banner">{notice}<button onClick={() => setNotice("")}>×</button></div>}
      <div className="metrics">
        <div className="metric-card"><span>Encryption active</span><strong>v{summary.keyrings.upstreamEncryption.activeVersion}</strong></div>
        <div className="metric-card"><span>Encryption versions</span><strong>{summary.keyrings.upstreamEncryption.configuredVersions.length}</strong></div>
        <div className="metric-card"><span>Signing active</span><strong>{summary.keyrings.capabilitySigning.activeKid}</strong></div>
        <div className="metric-card"><span>Signing generations</span><strong>{summary.keyrings.capabilitySigning.configuredKids.length}</strong></div>
      </div>
      <p className="fine-print">Only key/version identifiers are shown. Key material remains in Worker secrets.</p>
    </div>

    {newSecret && <div className="panel"><div className="panel-head"><div><h3>New agent key · version {newSecret.version}</h3><p>{newSecret.previousValidUntil ? `Previous key remains valid until ${utcDate(newSecret.previousValidUntil)}.` : "Previous key was invalidated immediately."}</p></div><button onClick={() => setNewSecret(null)}>Close</button></div><div className="secret-box"><code>{newSecret.value}</code><button onClick={() => navigator.clipboard.writeText(newSecret.value)}>Copy</button></div></div>}

    <div className="gateway-grid">
      {gateways.map((gateway) => <article className="gateway-card" key={gateway.id}>
        <div className="gateway-title"><div><h3>{gateway.name}</h3><p>{gateway.connection_mode === "cloudflare_access" ? "Tunnel + Access" : "Public HTTPS"}</p></div><span className="badge good">Encrypted v{gateway.upstream_secret_version || 1}</span></div>
        <div className="gateway-meta"><span>Credentials rotated: {utcDate(gateway.credentials_rotated_at)}</span></div>
        <div className="card-actions"><button onClick={() => loadKeys(gateway.id)}>Credential history</button></div>
        {manager && <GatewayCredentialRotation workspaceId={workspace.id} gateway={gateway} onRotated={async () => { setNotice("Gateway credentials rotated."); await load(); }} onError={setError} />}
        {expandedGateway === gateway.id && <div className="key-list">{(keys[gateway.id] || []).map((key) => <KeyRotationRow key={key.id} agentKey={key} onRotate={(overlap) => rotateKey(gateway.id, key.id, overlap)} />)}</div>}
      </article>)}
    </div>

    <div className="panel">
      <div className="panel-head"><div><h3>Security audit events</h3><p>Rotation events record actor, target, version metadata, and timing—never secret values.</p></div></div>
      {!summary.events.length ? <div className="table-empty">No secret lifecycle events yet.</div> : <div className="table-wrap"><table><thead><tr><th>Event</th><th>Actor</th><th>Target</th><th>Metadata</th><th>Time</th></tr></thead><tbody>{summary.events.map((event) => <tr key={event.id}><td><strong>{event.event_type}</strong></td><td>{event.actor_name || event.actor_email || "System"}</td><td>{event.target_type}<small>{event.target_id}</small></td><td><code>{event.metadata_json}</code></td><td>{utcDate(event.created_at)}</td></tr>)}</tbody></table></div>}
    </div>
  </section>;
}

function KeyRotationRow({ agentKey, onRotate }: { agentKey: AgentKey; onRotate: (overlapSeconds: number) => Promise<void> }) {
  const [overlap, setOverlap] = useState(300);
  return <div className="key-row"><div><strong>{agentKey.name}</strong><code>{agentKey.key_prefix}…</code><small>Secret v{agentKey.secret_version || 1} · rotated {utcDate(agentKey.secret_rotated_at)}</small>{agentKey.previous_secret_valid_until && <small>Previous generation valid until {utcDate(agentKey.previous_secret_valid_until)}</small>}</div><div className="key-controls">{agentKey.revoked_at ? <span className="badge bad">Revoked</span> : <><label>Overlap seconds<input type="number" min={0} max={86400} value={overlap} onChange={(e) => setOverlap(Number(e.target.value))} /></label><button className="primary-subtle" onClick={() => onRotate(overlap)}>Rotate key</button></>}</div></div>;
}

function GatewayCredentialRotation({ workspaceId, gateway, onRotated, onError }: { workspaceId: string; gateway: Gateway; onRotated: () => Promise<void>; onError: (value: string) => void }) {
  const [headers, setHeaders] = useState("");
  const [accessClientId, setAccessClientId] = useState("");
  const [accessClientSecret, setAccessClientSecret] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); onError("");
    try {
      const upstreamHeaders = headers.trim() ? JSON.parse(headers) : {};
      await api(`/v1/app/workspaces/${workspaceId}/gateways/${gateway.id}/credentials/rotate`, {
        method: "POST",
        body: JSON.stringify({ upstreamHeaders, ...(gateway.connection_mode === "cloudflare_access" ? { accessClientId, accessClientSecret } : {}) }),
      });
      setHeaders(""); setAccessClientId(""); setAccessClientSecret("");
      await onRotated();
    } catch (e) { onError(e instanceof Error ? e.message : "Could not rotate gateway credentials"); }
    finally { setBusy(false); }
  }

  return <form onSubmit={submit}><label>Replacement upstream headers <small>JSON; leave empty if none</small><textarea value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder={'{"Authorization":"Bearer …"}'} /></label>{gateway.connection_mode === "cloudflare_access" && <><label>Replacement Access Client ID<input value={accessClientId} onChange={(e) => setAccessClientId(e.target.value)} required /></label><label>Replacement Access Client Secret<input type="password" value={accessClientSecret} onChange={(e) => setAccessClientSecret(e.target.value)} required /></label></>}<button className="primary-subtle" disabled={busy}>{busy ? "Rotating…" : "Rotate upstream credentials"}</button></form>;
}
