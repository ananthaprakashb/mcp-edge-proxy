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
  chain_sequence: number | null;
  previous_hash: string | null;
  event_hash: string | null;
};

type SecuritySummary = {
  keyrings: {
    upstreamEncryption: { activeVersion: number; configuredVersions: number[] };
    capabilitySigning: { activeKid: string; configuredKids: string[] };
  };
};

type RetentionSummary = {
  policy: { traceRetentionDays: number; auditRetentionDays: number };
  storage: {
    traces: number;
    oldestTraceAt: string | null;
    auditEvents: number;
    oldestAuditEventAt: string | null;
  };
  integrity: {
    valid: boolean;
    checkedEvents: number;
    anchorSequence: number;
    headSequence: number;
    reason?: string;
  };
  lastRun: null | {
    id: string;
    trigger_type: string;
    status: string;
    traces_deleted: number;
    audit_events_deleted: number;
    integrity_failures: number;
    error_message: string | null;
    started_at: string;
    completed_at: string | null;
  };
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
  const [retention, setRetention] = useState<RetentionSummary | null>(null);
  const [auditEvents, setAuditEvents] = useState<SecurityEvent[]>([]);
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [keys, setKeys] = useState<Record<string, AgentKey[]>>({});
  const [expandedGateway, setExpandedGateway] = useState<string | null>(null);
  const [newSecret, setNewSecret] = useState<{ value: string; version: number; previousValidUntil: string | null } | null>(null);
  const [eventTypeFilter, setEventTypeFilter] = useState("");
  const [busyRetention, setBusyRetention] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    const [security, gatewayData, auditData, retentionData] = await Promise.all([
      api<SecuritySummary>(`/v1/app/workspaces/${workspace.id}/security`),
      api<{ gateways: Gateway[] }>(`/v1/app/workspaces/${workspace.id}/gateways`),
      api<{ events: SecurityEvent[] }>(`/v1/app/workspaces/${workspace.id}/audit?limit=100`),
      api<{ retention: RetentionSummary }>(`/v1/app/workspaces/${workspace.id}/retention`),
    ]);
    setSummary(security);
    setGateways(gatewayData.gateways);
    setAuditEvents(auditData.events);
    setRetention(retentionData.retention);
  }, [workspace.id]);

  useEffect(() => { void load().catch((e: unknown) => setError(e instanceof Error ? e.message : "Could not load security controls")); }, [load]);

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

  async function filterAudit(event: FormEvent) {
    event.preventDefault();
    setError("");
    const query = new URLSearchParams({ limit: "100" });
    if (eventTypeFilter.trim()) query.set("eventType", eventTypeFilter.trim());
    try {
      const data = await api<{ events: SecurityEvent[] }>(`/v1/app/workspaces/${workspace.id}/audit?${query}`);
      setAuditEvents(data.events);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not filter audit events"); }
  }

  async function runRetention() {
    setBusyRetention(true); setError(""); setNotice("");
    try {
      const result = await api<{ run: { tracesDeleted: number; auditEventsDeleted: number } }>(`/v1/app/workspaces/${workspace.id}/retention/run`, { method: "POST" });
      setNotice(`Retention cleanup completed: ${result.run.tracesDeleted} traces and ${result.run.auditEventsDeleted} audit events removed.`);
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Retention cleanup failed"); }
    finally { setBusyRetention(false); }
  }

  async function downloadAudit(format: "csv" | "json") {
    setError("");
    const query = new URLSearchParams({ format, limit: "5000" });
    if (eventTypeFilter.trim()) query.set("eventType", eventTypeFilter.trim());
    try {
      const response = await fetch(`/v1/app/workspaces/${workspace.id}/audit/export?${query}`, { credentials: "same-origin" });
      if (!response.ok) throw new Error(`Audit export failed with HTTP ${response.status}`);
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = href;
      link.download = `contextgateway-audit-${workspace.id}.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(href);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not export audit history"); }
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

    {retention && <div className="panel">
      <div className="panel-head"><div><h3>Audit retention & integrity</h3><p>Trace history expires sooner than durable security audit history. Audit cleanup verifies the hash chain before deleting records.</p></div>{manager && <button onClick={runRetention} disabled={busyRetention}>{busyRetention ? "Running…" : "Run cleanup"}</button>}</div>
      <div className="metrics">
        <div className="metric-card"><span>Trace retention</span><strong>{retention.policy.traceRetentionDays}d</strong></div>
        <div className="metric-card"><span>Audit retention</span><strong>{retention.policy.auditRetentionDays}d</strong></div>
        <div className="metric-card"><span>Stored traces</span><strong>{retention.storage.traces}</strong></div>
        <div className="metric-card"><span>Audit events</span><strong>{retention.storage.auditEvents}</strong></div>
        <div className="metric-card"><span>Integrity</span><strong>{retention.integrity.valid ? "Verified" : "FAILED"}</strong></div>
      </div>
      <p className="fine-print">Verified {retention.integrity.checkedEvents} retained audit events · anchor sequence {retention.integrity.anchorSequence} · head sequence {retention.integrity.headSequence}. Last cleanup: {retention.lastRun ? `${retention.lastRun.status} · ${utcDate(retention.lastRun.completed_at || retention.lastRun.started_at)}` : "Never"}.</p>
    </div>}

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
      <div className="panel-head"><div><h3>Security audit events</h3><p>Durable audit records are hash-chained and retained according to your plan.</p></div>{manager && <div className="card-actions"><button onClick={() => downloadAudit("csv")}>Export CSV</button><button onClick={() => downloadAudit("json")}>Export JSON</button></div>}</div>
      <form className="filters" onSubmit={filterAudit}><input value={eventTypeFilter} onChange={(e) => setEventTypeFilter(e.target.value)} placeholder="Filter exact event type" /><button>Apply</button><button type="button" onClick={() => { setEventTypeFilter(""); void load(); }}>Clear</button></form>
      {!auditEvents.length ? <div className="table-empty">No matching security audit events.</div> : <div className="table-wrap"><table><thead><tr><th>Event</th><th>Actor</th><th>Target</th><th>Integrity</th><th>Metadata</th><th>Time</th></tr></thead><tbody>{auditEvents.map((event) => <tr key={event.id}><td><strong>{event.event_type}</strong></td><td>{event.actor_name || event.actor_email || "System"}</td><td>{event.target_type}<small>{event.target_id}</small></td><td><small>#{event.chain_sequence ?? "—"}</small><code>{event.event_hash ? `${event.event_hash.slice(0, 12)}…` : "unsealed"}</code></td><td><code>{event.metadata_json}</code></td><td>{utcDate(event.created_at)}</td></tr>)}</tbody></table></div>}
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
