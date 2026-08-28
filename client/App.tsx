import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { api } from "./api";
import { authClient } from "./auth-client";

type Workspace = {
  id: string;
  account_id: string;
  name: string;
  slug: string;
  role: "owner" | "admin" | "member";
  plan: "free" | "pro" | "team";
  subscription_status: string;
};

type Gateway = {
  id: string;
  name: string;
  upstream_url: string;
  enabled: number;
  created_at: string;
  key_count: number;
  active_key_count: number;
};

type AgentKey = {
  id: string;
  name: string;
  key_prefix: string;
  allowed_methods: string;
  allowed_names: string;
  revoked_at: string | null;
  created_at: string;
};

type Trace = {
  id: string;
  request_id: string;
  gateway_id: string;
  gateway_name: string;
  api_key_id: string | null;
  key_name: string | null;
  mcp_method: string | null;
  mcp_name: string | null;
  decision: string;
  status_code: number;
  duration_ms: number;
  created_at: string;
};

type Config = { auth: { emailPassword: boolean; github: boolean; google: boolean } };
type Bootstrap = { user: { id: string; name: string; email: string; image?: string | null }; workspaces: Workspace[] };
type Overview = { workspace: Workspace; metrics: { gateways: number; activeKeys: number; requests24h: number; denied24h: number; avgLatencyMs: number } };
type Tab = "overview" | "gateways" | "traces";

function parseList(raw: string): string[] {
  return raw.split(",").map((item) => item.trim()).filter(Boolean);
}

function policyText(raw: string): string {
  try {
    return (JSON.parse(raw) as string[]).join(", ");
  } catch {
    return raw;
  }
}

function AuthScreen({ config }: { config: Config | null }) {
  const [mode, setMode] = useState<"sign-in" | "sign-up">("sign-in");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const result = mode === "sign-up"
      ? await authClient.signUp.email({ name, email, password })
      : await authClient.signIn.email({ email, password });
    setBusy(false);
    if (result.error) setError(result.error.message || "Authentication failed");
    else window.location.reload();
  }

  async function social(provider: "github" | "google") {
    await authClient.signIn.social({ provider, callbackURL: "/" });
  }

  return (
    <main className="auth-shell">
      <section className="auth-copy">
        <div className="brand-mark">CG</div>
        <p className="eyebrow">CONTEXTGATEWAY</p>
        <h1>The policy and audit firewall for MCP traffic.</h1>
        <p className="lede">Give agents least-privilege access to MCP tools, keep upstream credentials out of model context, and see every allow/deny decision without retaining prompts.</p>
        <div className="trust-row"><span>Scoped credentials</span><span>Metadata-only traces</span><span>Edge enforcement</span></div>
      </section>
      <section className="auth-card">
        <div className="mode-tabs">
          <button className={mode === "sign-in" ? "active" : ""} onClick={() => setMode("sign-in")}>Sign in</button>
          <button className={mode === "sign-up" ? "active" : ""} onClick={() => setMode("sign-up")}>Create account</button>
        </div>
        <h2>{mode === "sign-in" ? "Welcome back" : "Start securing agent traffic"}</h2>
        <form onSubmit={submit}>
          {mode === "sign-up" && <label>Name<input value={name} onChange={(e) => setName(e.target.value)} required /></label>}
          <label>Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
          <label>Password<input type="password" minLength={12} value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
          {error && <div className="error-banner">{error}</div>}
          <button className="primary wide" disabled={busy}>{busy ? "Working…" : mode === "sign-in" ? "Sign in" : "Create account"}</button>
        </form>
        {(config?.auth.github || config?.auth.google) && <div className="divider"><span>or continue with</span></div>}
        <div className="social-row">
          {config?.auth.github && <button onClick={() => social("github")}>GitHub</button>}
          {config?.auth.google && <button onClick={() => social("google")}>Google</button>}
        </div>
        <p className="fine-print">Social buttons appear only when provider credentials are configured. Sessions stay on the same Cloudflare Worker and D1 database.</p>
      </section>
    </main>
  );
}

function EmptyWorkspace({ onCreated }: { onCreated: () => Promise<void> }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError("");
    try {
      await api("/v1/app/workspaces", { method: "POST", body: JSON.stringify({ name }) });
      await onCreated();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not create workspace"); }
    finally { setBusy(false); }
  }
  return <div className="empty-state"><div className="brand-mark">CG</div><h2>Create your first workspace</h2><p>A workspace owns gateways, scoped agent credentials, policies, traces, and eventually billing.</p><form onSubmit={submit}><label>Workspace name<input value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme AI" required /></label>{error && <div className="error-banner">{error}</div>}<button className="primary" disabled={busy}>{busy ? "Creating…" : "Create workspace"}</button></form></div>;
}

function Metric({ label, value, suffix }: { label: string; value: number; suffix?: string }) {
  return <div className="metric-card"><span>{label}</span><strong>{value}{suffix}</strong></div>;
}

function Dashboard({ bootstrap }: { bootstrap: Bootstrap }) {
  const [workspaceId, setWorkspaceId] = useState(bootstrap.workspaces[0]?.id || "");
  const [tab, setTab] = useState<Tab>("overview");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [traces, setTraces] = useState<Trace[]>([]);
  const [keysByGateway, setKeysByGateway] = useState<Record<string, AgentKey[]>>({});
  const [traceDecision, setTraceDecision] = useState("");
  const [traceQuery, setTraceQuery] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [showGatewayForm, setShowGatewayForm] = useState(false);
  const [keyGateway, setKeyGateway] = useState<string | null>(null);
  const [newSecret, setNewSecret] = useState<string | null>(null);

  const workspace = useMemo(() => bootstrap.workspaces.find((w) => w.id === workspaceId) || bootstrap.workspaces[0], [bootstrap.workspaces, workspaceId]);
  const writable = workspace?.role === "owner" || workspace?.role === "admin";

  const loadOverview = useCallback(async () => {
    if (!workspace?.id) return;
    setOverview(await api<Overview>(`/v1/app/workspaces/${workspace.id}/overview`));
  }, [workspace?.id]);

  const loadGateways = useCallback(async () => {
    if (!workspace?.id) return;
    const data = await api<{ gateways: Gateway[] }>(`/v1/app/workspaces/${workspace.id}/gateways`);
    setGateways(data.gateways);
  }, [workspace?.id]);

  const loadTraces = useCallback(async () => {
    if (!workspace?.id) return;
    const params = new URLSearchParams({ limit: "100" });
    if (traceDecision) params.set("decision", traceDecision);
    if (traceQuery) params.set("q", traceQuery);
    const data = await api<{ traces: Trace[] }>(`/v1/app/workspaces/${workspace.id}/traces?${params}`);
    setTraces(data.traces);
  }, [workspace?.id, traceDecision, traceQuery]);

  useEffect(() => { void Promise.all([loadOverview(), loadGateways(), loadTraces()]).catch((e: unknown) => setError(e instanceof Error ? e.message : "Dashboard load failed")); }, [loadOverview, loadGateways, loadTraces]);

  async function loadKeys(gatewayId: string) {
    if (!workspace) return;
    const data = await api<{ keys: AgentKey[] }>(`/v1/app/workspaces/${workspace.id}/gateways/${gatewayId}/keys`);
    setKeysByGateway((current) => ({ ...current, [gatewayId]: data.keys }));
  }

  async function revoke(gatewayId: string, keyId: string) {
    if (!workspace || !confirm("Revoke this agent key? Existing clients using it will immediately fail authentication.")) return;
    await api(`/v1/app/workspaces/${workspace.id}/gateways/${gatewayId}/keys/${keyId}`, { method: "DELETE" });
    await Promise.all([loadKeys(gatewayId), loadOverview()]);
  }

  async function signOut() { await authClient.signOut(); window.location.reload(); }

  return <div className="app-shell">
    <aside className="sidebar">
      <div><div className="brand-inline"><div className="brand-mark small">CG</div><strong>ContextGateway</strong></div><div className="workspace-switch"><span>Workspace</span><select value={workspace?.id} onChange={(e) => setWorkspaceId(e.target.value)}>{bootstrap.workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}</select></div><nav>{(["overview", "gateways", "traces"] as Tab[]).map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => setTab(item)}>{item === "overview" ? "Overview" : item === "gateways" ? "Gateways & keys" : "Trace explorer"}</button>)}</nav></div>
      <div className="user-block"><div><strong>{bootstrap.user.name}</strong><span>{bootstrap.user.email}</span></div><button onClick={signOut}>Sign out</button></div>
    </aside>
    <main className="content">
      <header className="topbar"><div><p className="eyebrow">{workspace?.plan.toUpperCase()} PLAN · {workspace?.role.toUpperCase()}</p><h1>{tab === "overview" ? "Security overview" : tab === "gateways" ? "Gateways & agent credentials" : "MCP trace explorer"}</h1></div><div className="status-pill"><i /> Edge active</div></header>
      {error && <div className="error-banner">{error}<button onClick={() => setError("")}>×</button></div>}{notice && <div className="success-banner">{notice}<button onClick={() => setNotice("")}>×</button></div>}
      {tab === "overview" && <section><div className="metrics">{overview && <><Metric label="Active gateways" value={overview.metrics.gateways}/><Metric label="Active agent keys" value={overview.metrics.activeKeys}/><Metric label="Requests · 24h" value={overview.metrics.requests24h}/><Metric label="Denied · 24h" value={overview.metrics.denied24h}/><Metric label="Avg latency" value={overview.metrics.avgLatencyMs} suffix="ms"/></>}</div><div className="panel"><div className="panel-head"><div><h3>Recent policy decisions</h3><p>Metadata only — prompts, arguments, and response bodies are not stored.</p></div><button onClick={() => setTab("traces")}>Open explorer</button></div><TraceTable traces={traces.slice(0, 8)} /></div></section>}
      {tab === "gateways" && <section><div className="section-actions"><p>Each gateway maps one MCP endpoint to independently scoped agent credentials.</p>{writable && <button className="primary" onClick={() => setShowGatewayForm(true)}>+ New gateway</button>}</div><div className="gateway-grid">{gateways.map((g) => <article className="gateway-card" key={g.id}><div className="gateway-title"><div><h3>{g.name}</h3><code>{location.origin}/v1/mcp/{g.id}</code></div><span className={g.enabled ? "badge good" : "badge"}>{g.enabled ? "Active" : "Disabled"}</span></div><div className="upstream"><span>Upstream</span><code>{g.upstream_url}</code></div><div className="gateway-meta"><span>{Number(g.active_key_count || 0)} active keys</span><span>Created {new Date(g.created_at).toLocaleDateString()}</span></div><div className="card-actions"><button onClick={() => loadKeys(g.id)}>View keys</button>{writable && <button className="primary-subtle" onClick={() => setKeyGateway(g.id)}>Issue key</button>}</div>{keysByGateway[g.id] && <div className="key-list">{keysByGateway[g.id].map((k) => <div className="key-row" key={k.id}><div><strong>{k.name}</strong><code>{k.key_prefix}…</code><small>{policyText(k.allowed_names)}</small></div><span className={k.revoked_at ? "badge bad" : "badge good"}>{k.revoked_at ? "Revoked" : "Active"}</span>{writable && !k.revoked_at && <button className="danger-link" onClick={() => revoke(g.id, k.id)}>Revoke</button>}</div>)}</div>}</article>)}</div>{gateways.length === 0 && <div className="panel empty-panel">No gateways yet. Add the first MCP server to begin issuing scoped credentials.</div>}</section>}
      {tab === "traces" && <section><div className="filters"><input placeholder="Search tool, method, request ID" value={traceQuery} onChange={(e) => setTraceQuery(e.target.value)} /><select value={traceDecision} onChange={(e) => setTraceDecision(e.target.value)}><option value="">All decisions</option><option value="allowed">Allowed</option><option value="policy_denied">Policy denied</option><option value="unauthorized">Unauthorized</option><option value="rate_limited">Rate limited</option><option value="upstream_error">Upstream error</option></select><button onClick={() => loadTraces()}>Refresh</button></div><div className="panel"><TraceTable traces={traces} /></div></section>}
      {showGatewayForm && workspace && <GatewayModal workspace={workspace} onClose={() => setShowGatewayForm(false)} onCreated={async () => { setShowGatewayForm(false); setNotice("Gateway created. Issue a scoped agent key next."); await Promise.all([loadGateways(), loadOverview()]); }} />}
      {keyGateway && workspace && <KeyModal workspace={workspace} gatewayId={keyGateway} onClose={() => setKeyGateway(null)} onCreated={async (secret) => { const createdFor = keyGateway; setKeyGateway(null); setNewSecret(secret); if (createdFor) await Promise.all([loadKeys(createdFor), loadOverview()]); }} />}
      {newSecret && <SecretModal secret={newSecret} onClose={() => setNewSecret(null)} />}
    </main>
  </div>;
}

function TraceTable({ traces }: { traces: Trace[] }) {
  if (!traces.length) return <div className="table-empty">No trace records match this view.</div>;
  return <div className="table-wrap"><table><thead><tr><th>Decision</th><th>Tool / method</th><th>Gateway</th><th>Agent key</th><th>Status</th><th>Latency</th><th>Time</th></tr></thead><tbody>{traces.map((t) => <tr key={t.id}><td><span className={`badge ${t.decision === "allowed" ? "good" : t.decision === "policy_denied" ? "bad" : "warn"}`}>{t.decision}</span></td><td><strong>{t.mcp_name || "—"}</strong><small>{t.mcp_method || "unknown"}</small></td><td>{t.gateway_name}</td><td>{t.key_name || "—"}</td><td>{t.status_code}</td><td>{t.duration_ms} ms</td><td>{new Date(t.created_at + (t.created_at.endsWith("Z") ? "" : "Z")).toLocaleString()}</td></tr>)}</tbody></table></div>;
}

function GatewayModal({ workspace, onClose, onCreated }: { workspace: Workspace; onClose: () => void; onCreated: () => Promise<void> }) {
  const [name, setName] = useState(""); const [url, setUrl] = useState(""); const [headers, setHeaders] = useState(""); const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) { e.preventDefault(); setBusy(true); setError(""); try { let upstreamHeaders = {}; if (headers.trim()) upstreamHeaders = JSON.parse(headers); await api(`/v1/app/workspaces/${workspace.id}/gateways`, { method: "POST", body: JSON.stringify({ name, upstreamUrl: url, upstreamHeaders }) }); await onCreated(); } catch (err) { setError(err instanceof Error ? err.message : "Could not create gateway"); } finally { setBusy(false); } }
  return <div className="modal-backdrop"><div className="modal"><button className="modal-close" onClick={onClose}>×</button><p className="eyebrow">NEW GATEWAY</p><h2>Connect an MCP server</h2><p>HTTPS only. Upstream auth headers are encrypted before storage and never shown again.</p><form onSubmit={submit}><label>Name<input value={name} onChange={(e) => setName(e.target.value)} placeholder="GitHub tools" required /></label><label>MCP upstream URL<input type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://mcp.example.com/mcp" required /></label><label>Upstream headers <small>optional JSON</small><textarea value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder={'{"Authorization":"Bearer …"}'} /></label>{error && <div className="error-banner">{error}</div>}<button className="primary wide" disabled={busy}>{busy ? "Creating…" : "Create gateway"}</button></form></div></div>;
}

function KeyModal({ workspace, gatewayId, onClose, onCreated }: { workspace: Workspace; gatewayId: string; onClose: () => void; onCreated: (secret: string) => Promise<void> }) {
  const [name, setName] = useState(""); const [methods, setMethods] = useState("tools/list, tools/call"); const [names, setNames] = useState(""); const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) { e.preventDefault(); setBusy(true); setError(""); try { const data = await api<{ key: { key: string } }>(`/v1/app/workspaces/${workspace.id}/gateways/${gatewayId}/keys`, { method: "POST", body: JSON.stringify({ name, allowedMethods: parseList(methods), allowedNames: parseList(names) }) }); await onCreated(data.key.key); } catch (err) { setError(err instanceof Error ? err.message : "Could not issue key"); } finally { setBusy(false); } }
  return <div className="modal-backdrop"><div className="modal"><button className="modal-close" onClick={onClose}>×</button><p className="eyebrow">SCOPED AGENT KEY</p><h2>Issue least-privilege access</h2><form onSubmit={submit}><label>Credential name<input value={name} onChange={(e) => setName(e.target.value)} placeholder="coding-agent" required /></label><label>Allowed MCP methods<input value={methods} onChange={(e) => setMethods(e.target.value)} required /></label><label>Allowed tool names<input value={names} onChange={(e) => setNames(e.target.value)} placeholder="github.create_issue, github.add_comment" required /></label><p className="fine-print">Comma-separated exact names. Use standalone * only when intentionally granting every operation.</p>{error && <div className="error-banner">{error}</div>}<button className="primary wide" disabled={busy}>{busy ? "Issuing…" : "Issue agent key"}</button></form></div></div>;
}

function SecretModal({ secret, onClose }: { secret: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  async function copy() { await navigator.clipboard.writeText(secret); setCopied(true); }
  return <div className="modal-backdrop"><div className="modal"><p className="eyebrow">SHOWN ONCE</p><h2>Store this agent key now</h2><p>The plaintext value cannot be recovered from ContextGateway later.</p><div className="secret-box"><code>{secret}</code><button onClick={copy}>{copied ? "Copied" : "Copy"}</button></div><button className="primary wide" onClick={onClose}>I stored the key</button></div></div>;
}

export default function App() {
  const { data: session, isPending } = authClient.useSession();
  const [config, setConfig] = useState<Config | null>(null);
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [error, setError] = useState("");

  const refreshBootstrap = useCallback(async () => {
    const data = await api<Bootstrap>("/v1/app/bootstrap");
    setBootstrap(data);
  }, []);

  useEffect(() => { api<Config>("/v1/app/config").then(setConfig).catch(() => undefined); }, []);
  useEffect(() => { if (session?.user) refreshBootstrap().catch((e: unknown) => setError(e instanceof Error ? e.message : "Could not load workspace")); else setBootstrap(null); }, [session?.user?.id, refreshBootstrap]);

  if (isPending) return <div className="loading-screen"><div className="brand-mark">CG</div><span>Loading ContextGateway…</span></div>;
  if (!session?.user) return <AuthScreen config={config} />;
  if (error) return <div className="loading-screen"><div className="error-banner">{error}</div></div>;
  if (!bootstrap) return <div className="loading-screen"><div className="brand-mark">CG</div><span>Loading workspace…</span></div>;
  if (!bootstrap.workspaces.length) return <EmptyWorkspace onCreated={refreshBootstrap} />;
  return <Dashboard bootstrap={bootstrap} />;
}
