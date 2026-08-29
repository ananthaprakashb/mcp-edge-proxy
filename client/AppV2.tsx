import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { api } from "./api";
import { authClient } from "./auth-client";
import { ContextPanel } from "./ContextPanel";
import { InviteAcceptance } from "./InviteAcceptance";
import { OperationsPanel } from "./OperationsPanel";
import { TeamPanel } from "./TeamPanel";

type ExecutionMode = "direct" | "capability_required";
type AuthMode = "agent_key" | "capability";
type ConnectionMode = "public" | "cloudflare_access";
type Role = "owner" | "admin" | "member";
type Plan = "free" | "pro" | "team";
type Tab = "overview" | "gateways" | "context" | "traces" | "operations" | "team" | "billing";

type Workspace = { id: string; account_id: string; name: string; slug: string; role: Role; plan: Plan; subscription_status: string };
type Bootstrap = { user: { id: string; name: string; email: string; image?: string | null }; workspaces: Workspace[] };
type Config = { auth: { emailPassword: boolean; github: boolean; google: boolean } };
type Overview = { metrics: { gateways: number; activeKeys: number; requests24h: number; denied24h: number; avgLatencyMs: number } };
type Gateway = {
  id: string; name: string; upstream_url: string; connection_mode: ConnectionMode; enabled: number; created_at: string;
  key_count: number; active_key_count: number; health_status?: string; health_reason?: string | null; last_health_checked_at?: string | null;
};
type AgentKey = { id: string; name: string; key_prefix: string; allowed_methods: string; allowed_names: string; execution_mode: ExecutionMode; revoked_at: string | null; created_at: string };
type Trace = {
  id: string; request_id: string; gateway_id: string; gateway_name: string; connection_mode: ConnectionMode; api_key_id: string | null;
  key_name: string | null; execution_mode: ExecutionMode | null; mcp_method: string | null; mcp_name: string | null; decision: string;
  status_code: number; duration_ms: number; auth_mode: AuthMode | null; capability_jti: string | null; policy_reason: string | null;
  policy_method_rule: string | null; policy_name_rule: string | null; created_at: string;
};
type BillingSummary = {
  billing: { plan: Plan; subscription_status: string; billing_period_end: string | null; billing_cancel_at_period_end: number };
  entitlements: { displayName: string; monthlyPriceUsd: number; gatewayLimit: number; activeKeyLimit: number; memberLimit: number; monthlyRequestLimit: number };
  usage: { month: string; used: number; limit: number; remaining: number };
  resources: { gateways: number; activeKeys: number; members: number };
  stripe: { checkoutConfigured: boolean; webhookConfigured: boolean; hasCustomer: boolean };
};
type DocumentSummary = { id: string; documentKey: string };

type NavItem = { id: Tab; label: string; hint: string; icon: string; group: "protect" | "operate" };
const NAV: NavItem[] = [
  { id: "overview", label: "Overview", hint: "Posture & activity", icon: "grid", group: "protect" },
  { id: "gateways", label: "Gateways", hint: "MCP endpoints & keys", icon: "gateway", group: "protect" },
  { id: "context", label: "Governed context", hint: "Documents & policies", icon: "document", group: "protect" },
  { id: "traces", label: "Trace explorer", hint: "Decisions & latency", icon: "trace", group: "protect" },
  { id: "operations", label: "Operations", hint: "Health, secrets, audit", icon: "pulse", group: "operate" },
  { id: "team", label: "Team", hint: "Members & roles", icon: "team", group: "operate" },
  { id: "billing", label: "Billing & usage", hint: "Plan & quota", icon: "billing", group: "operate" },
];

function Icon({ name }: { name: string }) {
  const paths: Record<string, ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></>,
    gateway: <><path d="M4 6h16v12H4z"/><path d="M8 10h8M8 14h5"/><circle cx="17" cy="14" r="1"/></>,
    document: <><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5M9 12h6M9 16h6"/></>,
    trace: <><path d="M4 17l5-5 4 3 7-8"/><circle cx="4" cy="17" r="1.5"/><circle cx="9" cy="12" r="1.5"/><circle cx="13" cy="15" r="1.5"/><circle cx="20" cy="7" r="1.5"/></>,
    pulse: <><path d="M3 12h4l2-6 4 12 2-6h6"/></>,
    team: <><circle cx="9" cy="8" r="3"/><circle cx="17" cy="9" r="2.5"/><path d="M3 20c.5-4 2.5-6 6-6s5.5 2 6 6M14 15c3.5 0 5.5 1.5 6 5"/></>,
    billing: <><rect x="3" y="5" width="18" height="14" rx="3"/><path d="M3 9h18M7 15h4"/></>,
    menu: <><path d="M4 7h16M4 12h16M4 17h16"/></>,
    close: <><path d="M6 6l12 12M18 6L6 18"/></>,
    arrow: <><path d="M5 12h14M14 7l5 5-5 5"/></>,
    check: <><path d="M5 12l4 4L19 6"/></>,
    lock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/></>,
    plus: <><path d="M12 5v14M5 12h14"/></>,
  };
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] || paths.grid}</svg>;
}

function parseList(raw: string): string[] { return raw.split(",").map((item) => item.trim()).filter(Boolean); }
function policyText(raw: string): string { try { return (JSON.parse(raw) as string[]).join(", "); } catch { return raw; } }
function executionLabel(mode: ExecutionMode) { return mode === "capability_required" ? "Capability required" : "Direct compatible"; }
function connectionLabel(mode: ConnectionMode) { return mode === "cloudflare_access" ? "Tunnel + Access" : "Public HTTPS"; }
function utc(value: string) { return new Date(value + (value.endsWith("Z") ? "" : "Z")); }
function reasonLabel(reason: string | null) {
  if (!reason) return "No explanation recorded";
  const labels: Record<string, string> = {
    header_body_operation_mismatch: "MCP headers and JSON-RPC body disagreed",
    credential_missing: "No credential supplied",
    agent_key_invalid_or_revoked: "Agent key invalid or revoked",
    capability_signature_expiry_or_claims_invalid: "Capability signature, expiry, or claims invalid",
    capability_scope_mismatch: "Capability did not match this MCP method/tool",
    capability_arguments_digest_mismatch: "Arguments did not match the bound capability digest",
    capability_parent_key_revoked_or_mismatched: "Parent agent key was revoked or mismatched",
    key_requires_capability_exchange: "Direct execution blocked: this key requires a capability",
    subscription_inactive: "Subscription does not currently allow traffic",
    capability_single_use_already_consumed: "Capability was already consumed",
    "policy:missing_method": "Policy denied because the MCP method was missing",
    "policy:method_not_allowed": "MCP method was not allowed by the key policy",
    "policy:name_not_allowed": "Tool/resource name was not allowed by the key policy",
  };
  if (labels[reason]) return labels[reason];
  if (reason.includes("allowed_exact")) return "Allowed by exact MCP policy rules";
  if (reason.includes("allowed_wildcard")) return "Allowed by an MCP wildcard rule";
  return reason;
}

function AuthScreen({ config }: { config: Config | null }) {
  const [mode, setMode] = useState<"sign-in" | "sign-up">("sign-in");
  const [name, setName] = useState(""); const [email, setEmail] = useState(""); const [password, setPassword] = useState("");
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    const result = mode === "sign-up" ? await authClient.signUp.email({ name, email, password }) : await authClient.signIn.email({ email, password });
    setBusy(false); if (result.error) setError(result.error.message || "Authentication failed"); else window.location.reload();
  }
  async function social(provider: "github" | "google") { await authClient.signIn.social({ provider, callbackURL: `${window.location.pathname}${window.location.search}${window.location.hash}` }); }
  return <main className="auth-shell-v2">
    <section className="auth-story">
      <div className="brand-lockup"><div className="brand-symbol"><Icon name="lock" /></div><div><strong>ContextGateway</strong><span>Managed MCP security</span></div></div>
      <div className="auth-message"><span className="kicker">SECURE THE AGENT BOUNDARY</span><h1>Control what agents can <em>do</em> and what context they can <em>see</em>.</h1><p>Least-privilege MCP execution, isolated upstream credentials, governed context, and privacy-safe auditability at the edge.</p></div>
      <div className="auth-proof-grid"><div><strong>Single-use</strong><span>Capability tokens</span></div><div><strong>Fail-closed</strong><span>Network & document policy</span></div><div><strong>Metadata only</strong><span>Operational observability</span></div></div>
    </section>
    <section className="auth-panel"><div className="auth-card-v2"><span className="kicker">{mode === "sign-in" ? "WELCOME BACK" : "CREATE WORKSPACE"}</span><h2>{mode === "sign-in" ? "Sign in to ContextGateway" : "Start protecting MCP traffic"}</h2><p>Use your workspace identity to manage gateways, context policies, operations, and audit history.</p><div className="mode-tabs"><button className={mode === "sign-in" ? "active" : ""} onClick={() => setMode("sign-in")}>Sign in</button><button className={mode === "sign-up" ? "active" : ""} onClick={() => setMode("sign-up")}>Create account</button></div><form onSubmit={submit}>{mode === "sign-up" && <label>Name<input value={name} onChange={(e) => setName(e.target.value)} required /></label>}<label>Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required /></label><label>Password<input type="password" minLength={12} value={password} onChange={(e) => setPassword(e.target.value)} required /></label>{error && <div className="error-banner">{error}</div>}<button className="primary wide" disabled={busy}>{busy ? "Working…" : mode === "sign-in" ? "Sign in" : "Create account"}</button></form>{(config?.auth.github || config?.auth.google) && <><div className="divider"><span>or continue with</span></div><div className="social-row">{config?.auth.github && <button onClick={() => social("github")}>GitHub</button>}{config?.auth.google && <button onClick={() => social("google")}>Google</button>}</div></>}<p className="fine-print">ContextGateway does not expose stored upstream credentials, capability secrets, or governed document values in operational telemetry.</p></div></section>
  </main>;
}

function EmptyWorkspace({ onCreated }: { onCreated: () => Promise<void> }) {
  const [name, setName] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); setError(""); try { await api("/v1/app/workspaces", { method: "POST", body: JSON.stringify({ name }) }); await onCreated(); } catch (e) { setError(e instanceof Error ? e.message : "Could not create workspace"); } finally { setBusy(false); } }
  return <main className="setup-shell"><div className="setup-card"><div className="brand-symbol"><Icon name="lock" /></div><span className="kicker">FIRST STEP</span><h1>Create your security workspace</h1><p>Workspaces contain gateways, agent credentials, context policies, traces, operational controls, team access, and billing.</p><form onSubmit={submit}><label>Workspace name<input value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme AI Platform" required /></label>{error && <div className="error-banner">{error}</div>}<button className="primary" disabled={busy}>{busy ? "Creating…" : "Create workspace"}</button></form></div></main>;
}

function Metric({ label, value, suffix, detail }: { label: string; value: number; suffix?: string; detail?: string }) {
  return <div className="metric-card"><span>{label}</span><strong>{value.toLocaleString()}{suffix}</strong>{detail && <small>{detail}</small>}</div>;
}

function Onboarding({ gateways, activeKeys, requests, documents, onNavigate }: { gateways: number; activeKeys: number; requests: number; documents: number; onNavigate: (tab: Tab) => void }) {
  const steps = [
    { done: gateways > 0, title: "Connect an MCP gateway", body: "Register a public HTTPS or Tunnel + Access upstream.", tab: "gateways" as Tab },
    { done: activeKeys > 0, title: "Issue a scoped agent key", body: "Use capability-required mode for least privilege.", tab: "gateways" as Tab },
    { done: requests > 0, title: "Run a protected request", body: "Mint a single-use capability and inspect the decision.", tab: "traces" as Tab },
    { done: documents > 0, title: "Add governed context", body: "Version a document and grant an explicit path policy.", tab: "context" as Tab },
  ];
  const complete = steps.filter((step) => step.done).length;
  return <div className="panel onboarding-panel"><div className="panel-head"><div><span className="kicker">GET STARTED</span><h3>Security onboarding</h3><p>{complete} of {steps.length} foundation steps complete.</p></div><div className="progress-ring"><strong>{complete}/{steps.length}</strong></div></div><div className="onboarding-list">{steps.map((step, index) => <button key={step.title} className={`onboarding-step ${step.done ? "done" : ""}`} onClick={() => onNavigate(step.tab)}><span className="step-number">{step.done ? <Icon name="check" /> : index + 1}</span><span><strong>{step.title}</strong><small>{step.body}</small></span><Icon name="arrow" /></button>)}</div></div>;
}

function Dashboard({ bootstrap }: { bootstrap: Bootstrap }) {
  const [workspaceId, setWorkspaceId] = useState(bootstrap.workspaces[0]?.id || ""); const [tab, setTab] = useState<Tab>("overview");
  const [overview, setOverview] = useState<Overview | null>(null); const [billing, setBilling] = useState<BillingSummary | null>(null);
  const [gateways, setGateways] = useState<Gateway[]>([]); const [traces, setTraces] = useState<Trace[]>([]); const [documentCount, setDocumentCount] = useState(0);
  const [keysByGateway, setKeysByGateway] = useState<Record<string, AgentKey[]>>({}); const [traceDecision, setTraceDecision] = useState(""); const [traceAuthMode, setTraceAuthMode] = useState(""); const [traceQuery, setTraceQuery] = useState("");
  const [notice, setNotice] = useState(""); const [error, setError] = useState(""); const [showGatewayForm, setShowGatewayForm] = useState(false); const [keyGateway, setKeyGateway] = useState<string | null>(null); const [newSecret, setNewSecret] = useState<{ secret: string; executionMode: ExecutionMode } | null>(null); const [billingBusy, setBillingBusy] = useState(false); const [mobileNav, setMobileNav] = useState(false);
  const workspace = useMemo(() => bootstrap.workspaces.find((w) => w.id === workspaceId) || bootstrap.workspaces[0], [bootstrap.workspaces, workspaceId]); const writable = workspace?.role === "owner" || workspace?.role === "admin";

  const loadOverview = useCallback(async () => { if (workspace?.id) setOverview(await api<Overview>(`/v1/app/workspaces/${workspace.id}/overview`)); }, [workspace?.id]);
  const loadBilling = useCallback(async () => { if (workspace?.id) setBilling(await api<BillingSummary>(`/v1/app/workspaces/${workspace.id}/billing`)); }, [workspace?.id]);
  const loadGateways = useCallback(async () => { if (!workspace?.id) return; const data = await api<{ gateways: Gateway[] }>(`/v1/app/workspaces/${workspace.id}/gateways`); setGateways(data.gateways); }, [workspace?.id]);
  const loadDocuments = useCallback(async () => { if (!workspace?.id) return; try { const data = await api<{ documents: DocumentSummary[] }>(`/v1/app/workspaces/${workspace.id}/documents`); setDocumentCount(data.documents.length); } catch { setDocumentCount(0); } }, [workspace?.id]);
  const loadTraces = useCallback(async () => { if (!workspace?.id) return; const params = new URLSearchParams({ limit: "100" }); if (traceDecision) params.set("decision", traceDecision); if (traceAuthMode) params.set("authMode", traceAuthMode); if (traceQuery) params.set("q", traceQuery); const data = await api<{ traces: Trace[] }>(`/v1/app/workspaces/${workspace.id}/traces?${params}`); setTraces(data.traces); }, [workspace?.id, traceDecision, traceAuthMode, traceQuery]);
  useEffect(() => { setKeysByGateway({}); void Promise.all([loadOverview(), loadBilling(), loadGateways(), loadDocuments(), loadTraces()]).catch((e: unknown) => setError(e instanceof Error ? e.message : "Dashboard load failed")); }, [loadOverview, loadBilling, loadGateways, loadDocuments, loadTraces]);

  async function loadKeys(gatewayId: string) { if (!workspace) return; const data = await api<{ keys: AgentKey[] }>(`/v1/app/workspaces/${workspace.id}/gateways/${gatewayId}/keys`); setKeysByGateway((current) => ({ ...current, [gatewayId]: data.keys })); }
  async function updateKeyMode(gatewayId: string, keyId: string, executionMode: ExecutionMode) { if (!workspace) return; try { await api(`/v1/app/workspaces/${workspace.id}/gateways/${gatewayId}/keys/${keyId}`, { method: "PATCH", body: JSON.stringify({ executionMode }) }); setNotice(executionMode === "capability_required" ? "Key now requires a short-lived capability." : "Key now permits direct compatible execution."); await loadKeys(gatewayId); } catch (e) { setError(e instanceof Error ? e.message : "Could not update key"); } }
  async function revoke(gatewayId: string, keyId: string) { if (!workspace || !confirm("Revoke this agent key? Outstanding capabilities rooted in it will fail immediately.")) return; await api(`/v1/app/workspaces/${workspace.id}/gateways/${gatewayId}/keys/${keyId}`, { method: "DELETE" }); await Promise.all([loadKeys(gatewayId), loadOverview(), loadBilling()]); }
  async function checkout(plan: "pro" | "team") { if (!workspace) return; setBillingBusy(true); try { const data = await api<{ url: string }>(`/v1/app/workspaces/${workspace.id}/billing/checkout`, { method: "POST", body: JSON.stringify({ plan }) }); window.location.assign(data.url); } catch (e) { setError(e instanceof Error ? e.message : "Could not start checkout"); setBillingBusy(false); } }
  async function openPortal() { if (!workspace) return; setBillingBusy(true); try { const data = await api<{ url: string }>(`/v1/app/workspaces/${workspace.id}/billing/portal`, { method: "POST" }); window.location.assign(data.url); } catch (e) { setError(e instanceof Error ? e.message : "Could not open billing portal"); setBillingBusy(false); } }
  async function signOut() { await authClient.signOut(); window.location.reload(); }
  function navigate(next: Tab) { setTab(next); setMobileNav(false); window.scrollTo({ top: 0, behavior: "smooth" }); }

  const activeNav = NAV.find((item) => item.id === tab)!; const plan = billing?.billing.plan || workspace?.plan || "free";
  const healthyCount = gateways.filter((gateway) => gateway.health_status === "healthy").length; const unhealthyCount = gateways.filter((gateway) => gateway.health_status && gateway.health_status !== "healthy" && gateway.health_status !== "unknown").length;

  return <div className="app-shell-v2">
    {mobileNav && <button className="nav-scrim" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
    <aside className={`sidebar-v2 ${mobileNav ? "open" : ""}`}>
      <div className="sidebar-top"><div className="brand-lockup compact"><div className="brand-symbol"><Icon name="lock" /></div><div><strong>ContextGateway</strong><span>MCP security plane</span></div></div><button className="mobile-close" onClick={() => setMobileNav(false)}><Icon name="close" /></button></div>
      <div className="workspace-picker"><span>Workspace</span><select value={workspace?.id} onChange={(e) => setWorkspaceId(e.target.value)}>{bootstrap.workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}</select><div className="workspace-meta"><span className="badge good">{plan}</span><span>{workspace?.role}</span></div></div>
      <nav className="nav-groups"><NavGroup label="Protect" items={NAV.filter((item) => item.group === "protect")} active={tab} onSelect={navigate}/><NavGroup label="Operate" items={NAV.filter((item) => item.group === "operate")} active={tab} onSelect={navigate}/></nav>
      <div className="sidebar-foot"><div className="edge-state"><span className="state-dot"/><div><strong>Edge active</strong><small>Policy enforcement online</small></div></div><div className="user-card"><div className="avatar">{bootstrap.user.name?.slice(0, 1).toUpperCase() || "U"}</div><div className="user-copy"><strong>{bootstrap.user.name}</strong><span>{bootstrap.user.email}</span></div><button onClick={signOut}>Sign out</button></div></div>
    </aside>
    <main className="main-v2">
      <header className="header-v2"><button className="mobile-menu" onClick={() => setMobileNav(true)}><Icon name="menu" /></button><div><div className="breadcrumb"><span>{workspace?.name}</span><b>/</b><span>{activeNav.label}</span></div><h1>{activeNav.label}</h1><p>{activeNav.hint}</p></div><div className="header-actions"><span className="privacy-chip"><Icon name="lock" /> Privacy-safe telemetry</span></div></header>
      <div className="page-content">
        {error && <div className="error-banner floating-banner">{error}<button onClick={() => setError("")}>×</button></div>}{notice && <div className="success-banner floating-banner">{notice}<button onClick={() => setNotice("")}>×</button></div>}
        {tab === "overview" && <section className="stack-lg">
          <div className="hero-card"><div><span className="kicker">SECURITY POSTURE</span><h2>Your MCP control plane at a glance.</h2><p>Protect agent execution, isolate upstream credentials, govern context, and retain explainable metadata without storing prompts or response bodies.</p><div className="hero-actions">{writable && <button className="primary" onClick={() => { setShowGatewayForm(true); }}><Icon name="plus"/> Connect gateway</button>}<button onClick={() => navigate("traces")}>Inspect decisions <Icon name="arrow"/></button></div></div><div className="hero-status"><div><span>Gateway health</span><strong>{healthyCount}/{gateways.length || 0}</strong><small>{unhealthyCount ? `${unhealthyCount} need attention` : gateways.length ? "No active failures" : "Connect your first gateway"}</small></div><div><span>Governed docs</span><strong>{documentCount}</strong><small>Versioned context sources</small></div></div></div>
          <div className="metrics">{overview && <><Metric label="Active gateways" value={overview.metrics.gateways} detail="Protected MCP routes"/><Metric label="Active agent keys" value={overview.metrics.activeKeys} detail="Scoped identities"/><Metric label="Requests · 24h" value={overview.metrics.requests24h} detail="Authorized + denied"/><Metric label="Denied · 24h" value={overview.metrics.denied24h} detail="Policy interventions"/><Metric label="Avg latency" value={overview.metrics.avgLatencyMs} suffix="ms" detail="Edge request time"/></>}</div>
          <div className="overview-grid"><Onboarding gateways={overview?.metrics.gateways || 0} activeKeys={overview?.metrics.activeKeys || 0} requests={overview?.metrics.requests24h || 0} documents={documentCount} onNavigate={navigate}/><div className="panel"><div className="panel-head"><div><span className="kicker">RECENT ACTIVITY</span><h3>Policy decisions</h3><p>Latest request metadata and explainable enforcement outcomes.</p></div><button onClick={() => navigate("traces")}>Open explorer</button></div><TraceTable traces={traces.slice(0, 6)} compact /></div></div>
        </section>}
        {tab === "gateways" && <GatewaysPage gateways={gateways} writable={Boolean(writable)} keysByGateway={keysByGateway} onNew={() => setShowGatewayForm(true)} onLoadKeys={loadKeys} onIssueKey={setKeyGateway} onUpdateMode={updateKeyMode} onRevoke={revoke}/>} 
        {tab === "context" && workspace && <ContextPanel workspace={workspace}/>} 
        {tab === "traces" && <section className="stack-lg"><div className="filter-bar"><div className="search-field"><Icon name="trace"/><input placeholder="Search tool, method, request ID, reason, capability JTI" value={traceQuery} onChange={(e) => setTraceQuery(e.target.value)}/></div><select value={traceDecision} onChange={(e) => setTraceDecision(e.target.value)}><option value="">All decisions</option><option value="allowed">Allowed</option><option value="capability_required">Capability required</option><option value="policy_denied">Policy denied</option><option value="capability_scope_denied">Capability scope denied</option><option value="capability_arguments_denied">Capability arguments denied</option><option value="capability_replayed">Capability replayed</option><option value="unauthorized">Unauthorized</option><option value="rate_limited">Rate limited</option><option value="quota_exceeded">Quota exceeded</option><option value="upstream_error">Upstream error</option></select><select value={traceAuthMode} onChange={(e) => setTraceAuthMode(e.target.value)}><option value="">All auth modes</option><option value="agent_key">Agent key</option><option value="capability">Capability</option></select><button onClick={() => void loadTraces()}>Refresh</button></div><div className="panel"><div className="panel-head"><div><span className="kicker">TRACE EXPLORER</span><h3>Request decisions</h3><p>No prompt, argument payload, capability token, Access secret, or response body is retained.</p></div><span className="count-chip">{traces.length} records</span></div><TraceTable traces={traces}/></div></section>}
        {tab === "operations" && workspace && <OperationsPanel workspace={workspace}/>} 
        {tab === "team" && workspace && <TeamPanel workspace={workspace}/>} 
        {tab === "billing" && workspace && <BillingPanel summary={billing} owner={workspace.role === "owner"} busy={billingBusy} onCheckout={checkout} onPortal={openPortal} onRefresh={loadBilling}/>} 
      </div>
      {showGatewayForm && workspace && <GatewayModal workspace={workspace} onClose={() => setShowGatewayForm(false)} onCreated={async () => { setShowGatewayForm(false); setNotice("Gateway created. Issue a capability-required key next."); await Promise.all([loadGateways(), loadOverview(), loadBilling()]); }}/>} 
      {keyGateway && workspace && <KeyModal workspace={workspace} gatewayId={keyGateway} onClose={() => setKeyGateway(null)} onCreated={async (secret, executionMode) => { const id = keyGateway; setKeyGateway(null); setNewSecret({ secret, executionMode }); if (id) await Promise.all([loadKeys(id), loadOverview(), loadBilling()]); }}/>} 
      {newSecret && <SecretModal secret={newSecret.secret} executionMode={newSecret.executionMode} onClose={() => setNewSecret(null)}/>} 
    </main>
  </div>;
}

function NavGroup({ label, items, active, onSelect }: { label: string; items: NavItem[]; active: Tab; onSelect: (tab: Tab) => void }) {
  return <div className="nav-group"><span className="nav-label">{label}</span>{items.map((item) => <button key={item.id} className={active === item.id ? "active" : ""} onClick={() => onSelect(item.id)}><span className="nav-icon"><Icon name={item.icon}/></span><span><strong>{item.label}</strong><small>{item.hint}</small></span></button>)}</div>;
}

function GatewaysPage({ gateways, writable, keysByGateway, onNew, onLoadKeys, onIssueKey, onUpdateMode, onRevoke }: { gateways: Gateway[]; writable: boolean; keysByGateway: Record<string, AgentKey[]>; onNew: () => void; onLoadKeys: (id: string) => Promise<void>; onIssueKey: (id: string) => void; onUpdateMode: (gatewayId: string, keyId: string, mode: ExecutionMode) => Promise<void>; onRevoke: (gatewayId: string, keyId: string) => Promise<void> }) {
  return <section className="stack-lg"><div className="page-intro-card"><div><span className="kicker">MCP EDGE</span><h2>Gateways and agent identities</h2><p>Connect upstream MCP services, issue scoped credentials, and prefer capability-required execution for untrusted executors.</p></div>{writable && <button className="primary" onClick={onNew}><Icon name="plus"/> New gateway</button>}</div>{!gateways.length ? <div className="empty-panel-v2"><div className="empty-icon"><Icon name="gateway"/></div><h3>No gateways connected</h3><p>Start with a public HTTPS endpoint or a private service behind Cloudflare Tunnel + Access.</p>{writable && <button className="primary" onClick={onNew}>Connect first gateway</button>}</div> : <div className="gateway-grid-v2">{gateways.map((g) => <article className="gateway-card-v2" key={g.id}><div className="gateway-card-head"><div><div className="gateway-name-row"><h3>{g.name}</h3><span className={`health-dot ${g.health_status || "unknown"}`} title={g.health_status || "unknown"}/></div><code>{location.origin}/v1/mcp/{g.id}</code></div><div className="badge-row"><span className={g.enabled ? "badge good" : "badge"}>{g.enabled ? "Active" : "Disabled"}</span><span className="badge">{connectionLabel(g.connection_mode)}</span></div></div><div className="upstream-v2"><span>UPSTREAM</span><code>{g.upstream_url}</code></div><div className="gateway-stats"><div><strong>{Number(g.active_key_count || 0)}</strong><span>active keys</span></div><div><strong>{g.health_status || "unknown"}</strong><span>health</span></div><div><strong>{g.last_health_checked_at ? utc(g.last_health_checked_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "—"}</strong><span>last check</span></div></div><div className="card-actions"><button onClick={() => void onLoadKeys(g.id)}>Manage keys</button>{writable && <button className="primary-subtle" onClick={() => onIssueKey(g.id)}>Issue key</button>}</div>{keysByGateway[g.id] && <div className="key-list-v2">{!keysByGateway[g.id].length ? <div className="table-empty">No agent keys for this gateway.</div> : keysByGateway[g.id].map((k) => <div className="key-row-v2" key={k.id}><div><div className="key-name-row"><strong>{k.name}</strong><span className={`badge ${k.revoked_at ? "bad" : k.execution_mode === "capability_required" ? "good" : "warn"}`}>{k.revoked_at ? "Revoked" : executionLabel(k.execution_mode)}</span></div><code>{k.key_prefix}…</code><small>{policyText(k.allowed_names)}</small></div><div className="key-controls">{writable && !k.revoked_at && <select value={k.execution_mode} onChange={(e) => void onUpdateMode(g.id, k.id, e.target.value as ExecutionMode)}><option value="capability_required">Capability required</option><option value="direct">Direct compatible</option></select>}{writable && !k.revoked_at && <button className="danger-link" onClick={() => void onRevoke(g.id, k.id)}>Revoke</button>}</div></div>)}</div>}</article>)}</div>}</section>;
}

function TraceTable({ traces, compact = false }: { traces: Trace[]; compact?: boolean }) {
  if (!traces.length) return <div className="table-empty"><strong>No trace records</strong><span>Protected MCP traffic will appear here after requests are made.</span></div>;
  return <div className="table-wrap"><table className={compact ? "compact-table" : ""}><thead><tr><th>Decision</th><th>Tool / method</th>{!compact && <th>Auth</th>}<th>Why</th><th>Gateway</th>{!compact && <><th>Agent key</th><th>Status</th></>}<th>Latency</th><th>Time</th></tr></thead><tbody>{traces.map((t) => <tr key={t.id}><td><span className={`badge ${t.decision === "allowed" ? "good" : t.decision === "policy_denied" || t.decision === "quota_exceeded" || t.decision === "capability_required" || t.decision.includes("denied") ? "bad" : "warn"}`}>{t.decision}</span></td><td><strong>{t.mcp_name || "—"}</strong><small>{t.mcp_method || "unknown"}</small></td>{!compact && <td><strong>{t.auth_mode === "capability" ? "Capability" : t.auth_mode === "agent_key" ? "Agent key" : "—"}</strong>{t.capability_jti && <small title={t.capability_jti}>JTI {t.capability_jti.slice(0, 10)}…</small>}</td>}<td className="reason-cell"><strong>{reasonLabel(t.policy_reason)}</strong>{(t.policy_method_rule || t.policy_name_rule) && <small>method: {t.policy_method_rule || "—"} · name: {t.policy_name_rule || "—"}</small>}</td><td><strong>{t.gateway_name}</strong><small>{connectionLabel(t.connection_mode)}</small></td>{!compact && <><td><strong>{t.key_name || "—"}</strong>{t.execution_mode && <small>{executionLabel(t.execution_mode)}</small>}</td><td>{t.status_code}</td></>}<td>{t.duration_ms} ms</td><td>{utc(t.created_at).toLocaleString()}</td></tr>)}</tbody></table></div>;
}

function BillingPanel({ summary, owner, busy, onCheckout, onPortal, onRefresh }: { summary: BillingSummary | null; owner: boolean; busy: boolean; onCheckout: (plan: "pro" | "team") => Promise<void>; onPortal: () => Promise<void>; onRefresh: () => Promise<void> }) {
  if (!summary) return <div className="panel loading-panel">Loading billing and usage…</div>;
  const percent = summary.usage.limit ? Math.min(100, Math.round((summary.usage.used / summary.usage.limit) * 100)) : 0; const activePaid = summary.billing.plan !== "free" && ["active", "trialing"].includes(summary.billing.subscription_status);
  const plans = [{ id: "free" as Plan, name: "Free", price: "$0", gateway: 1, keys: 2, members: 1, requests: "10k" }, { id: "pro" as Plan, name: "Pro", price: "$19", gateway: 10, keys: 25, members: 3, requests: "100k" }, { id: "team" as Plan, name: "Team", price: "$49", gateway: 50, keys: 100, members: 15, requests: "1M" }];
  return <section className="stack-lg"><div className="metrics metrics-four"><Metric label="Requests this month" value={summary.usage.used} detail={`${percent}% of quota`}/><Metric label="Requests remaining" value={summary.usage.remaining} detail={summary.usage.month}/><Metric label="Active gateways" value={summary.resources.gateways} detail={`${summary.entitlements.gatewayLimit} plan limit`}/><Metric label="Team members" value={summary.resources.members} detail={`${summary.entitlements.memberLimit} plan limit`}/></div><div className="panel"><div className="panel-head"><div><span className="kicker">CURRENT PLAN</span><h3>{summary.entitlements.displayName}</h3><p>{summary.billing.subscription_status} · {summary.usage.limit.toLocaleString()} requests/month.</p></div><div className="card-actions"><button onClick={() => void onRefresh()}>Refresh</button>{owner && summary.stripe.hasCustomer && <button className="primary-subtle" disabled={busy} onClick={() => void onPortal()}>Manage billing</button>}</div></div>{summary.billing.billing_cancel_at_period_end === 1 && <div className="panel-body"><div className="error-banner">Cancellation is scheduled{summary.billing.billing_period_end ? ` for ${new Date(summary.billing.billing_period_end).toLocaleDateString()}` : ""}.</div></div>}</div><div className="plan-grid">{plans.map((p) => <article className={`plan-card ${summary.billing.plan === p.id ? "current" : ""}`} key={p.id}><div className="plan-head"><div><span className="kicker">{p.name.toUpperCase()}</span><h3>{p.price}<small>/month</small></h3></div>{summary.billing.plan === p.id && <span className="badge good">Current</span>}</div><ul><li>{p.gateway} gateways</li><li>{p.keys} active keys</li><li>{p.members} members</li><li>{p.requests} requests/month</li></ul>{owner && (p.id === "pro" || p.id === "team") && !activePaid && <button className="primary wide" disabled={busy || !summary.stripe.checkoutConfigured || !summary.stripe.webhookConfigured} onClick={() => void onCheckout(p.id as "pro" | "team")}>Upgrade to {p.name}</button>}</article>)}</div>{!owner && <div className="panel"><div className="panel-body">Only the workspace owner can change billing.</div></div>}</section>;
}

function GatewayModal({ workspace, onClose, onCreated }: { workspace: Workspace; onClose: () => void; onCreated: () => Promise<void> }) {
  const [name, setName] = useState(""); const [url, setUrl] = useState(""); const [headers, setHeaders] = useState(""); const [connectionMode, setConnectionMode] = useState<ConnectionMode>("public"); const [accessClientId, setAccessClientId] = useState(""); const [accessClientSecret, setAccessClientSecret] = useState(""); const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) { e.preventDefault(); setBusy(true); setError(""); try { let upstreamHeaders = {}; if (headers.trim()) upstreamHeaders = JSON.parse(headers); await api(`/v1/app/workspaces/${workspace.id}/gateways`, { method: "POST", body: JSON.stringify({ name, upstreamUrl: url, upstreamHeaders, connectionMode, ...(connectionMode === "cloudflare_access" ? { accessClientId, accessClientSecret } : {}) }) }); await onCreated(); } catch (err) { setError(err instanceof Error ? err.message : "Could not create gateway"); } finally { setBusy(false); } }
  return <Modal onClose={onClose} kicker="NEW GATEWAY" title="Connect an MCP server"><p>Use public HTTPS or a private origin through Cloudflare Tunnel + Access. Stored upstream credentials are encrypted and never displayed again.</p><form onSubmit={submit}><label>Name<input value={name} onChange={(e) => setName(e.target.value)} placeholder="Internal GitHub tools" required/></label><label>Connection mode<select value={connectionMode} onChange={(e) => setConnectionMode(e.target.value as ConnectionMode)}><option value="public">Public HTTPS</option><option value="cloudflare_access">Cloudflare Tunnel + Access</option></select></label><label>MCP upstream URL<input type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://mcp.example.com/mcp" required/></label>{connectionMode === "cloudflare_access" && <><label>Access Client ID<input value={accessClientId} onChange={(e) => setAccessClientId(e.target.value)} autoComplete="off" required/></label><label>Access Client Secret<input type="password" value={accessClientSecret} onChange={(e) => setAccessClientSecret(e.target.value)} autoComplete="new-password" required/></label></>}<label>Other upstream headers <small>optional JSON</small><textarea value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder={'{"Authorization":"Bearer …"}'}/></label>{error && <div className="error-banner">{error}</div>}<button className="primary wide" disabled={busy}>{busy ? "Creating…" : "Create gateway"}</button></form></Modal>;
}

function KeyModal({ workspace, gatewayId, onClose, onCreated }: { workspace: Workspace; gatewayId: string; onClose: () => void; onCreated: (secret: string, mode: ExecutionMode) => Promise<void> }) {
  const [name, setName] = useState(""); const [methods, setMethods] = useState("tools/list, tools/call"); const [names, setNames] = useState(""); const [executionMode, setExecutionMode] = useState<ExecutionMode>("capability_required"); const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) { e.preventDefault(); setBusy(true); setError(""); try { const data = await api<{ key: { key: string; executionMode: ExecutionMode } }>(`/v1/app/workspaces/${workspace.id}/gateways/${gatewayId}/keys`, { method: "POST", body: JSON.stringify({ name, allowedMethods: parseList(methods), allowedNames: parseList(names), executionMode }) }); await onCreated(data.key.key, data.key.executionMode); } catch (err) { setError(err instanceof Error ? err.message : "Could not issue key"); } finally { setBusy(false); } }
  return <Modal onClose={onClose} kicker="SCOPED AGENT KEY" title="Issue least-privilege access"><form onSubmit={submit}><label>Credential name<input value={name} onChange={(e) => setName(e.target.value)} placeholder="coding-agent" required/></label><label>Execution mode<select value={executionMode} onChange={(e) => setExecutionMode(e.target.value as ExecutionMode)}><option value="capability_required">Capability required (recommended)</option><option value="direct">Direct compatible</option></select></label><div className="info-box"><Icon name="lock"/><span>Capability-required keys mint short-lived single-use tokens but cannot invoke MCP operations directly.</span></div><label>Allowed MCP methods<input value={methods} onChange={(e) => setMethods(e.target.value)} required/></label><label>Allowed tool names<input value={names} onChange={(e) => setNames(e.target.value)} placeholder="github.create_issue, github.add_comment" required/></label>{error && <div className="error-banner">{error}</div>}<button className="primary wide" disabled={busy}>{busy ? "Issuing…" : "Issue agent key"}</button></form></Modal>;
}

function SecretModal({ secret, executionMode, onClose }: { secret: string; executionMode: ExecutionMode; onClose: () => void }) {
  const [copied, setCopied] = useState(false); async function copy() { await navigator.clipboard.writeText(secret); setCopied(true); }
  return <Modal kicker="SHOWN ONCE" title="Store this agent key now"><p>{executionMode === "capability_required" ? "Keep the reusable key with the trusted orchestrator. Give executors only the cg_cap_* tokens it mints." : "The plaintext value cannot be recovered later."}</p><div className="secret-box"><code>{secret}</code><button onClick={() => void copy()}>{copied ? "Copied" : "Copy key"}</button></div><span className={`badge ${executionMode === "capability_required" ? "good" : "warn"}`}>{executionLabel(executionMode)}</span><button className="primary wide" onClick={onClose}>I stored the key</button></Modal>;
}

function Modal({ onClose, kicker, title, children }: { onClose?: () => void; kicker: string; title: string; children: ReactNode }) { return <div className="modal-backdrop"><div className="modal-v2">{onClose && <button className="modal-close" onClick={onClose}><Icon name="close"/></button>}<span className="kicker">{kicker}</span><h2>{title}</h2>{children}</div></div>; }

export default function AppV2() {
  const { data: session, isPending } = authClient.useSession(); const [config, setConfig] = useState<Config | null>(null); const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null); const [error, setError] = useState(""); const [inviteToken, setInviteToken] = useState<string | null>(() => new URLSearchParams(window.location.hash.replace(/^#/, "")).get("invite"));
  const refreshBootstrap = useCallback(async () => { setBootstrap(await api<Bootstrap>("/v1/app/bootstrap")); }, []);
  function cancelInvite() { const url = new URL(window.location.href); const hash = new URLSearchParams(url.hash.replace(/^#/, "")); hash.delete("invite"); url.hash = hash.toString() ? `#${hash.toString()}` : ""; window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`); setInviteToken(null); }
  useEffect(() => { void api<Config>("/v1/app/config").then(setConfig).catch(() => undefined); }, []);
  useEffect(() => { if (session?.user) void refreshBootstrap().catch((e: unknown) => setError(e instanceof Error ? e.message : "Could not load workspace")); else setBootstrap(null); }, [session?.user?.id, refreshBootstrap]);
  if (isPending) return <div className="loading-screen"><div className="brand-symbol"><Icon name="lock"/></div><span>Loading ContextGateway…</span></div>;
  if (!session?.user) return <AuthScreen config={config}/>;
  if (error) return <div className="loading-screen"><div className="error-banner">{error}</div></div>;
  if (!bootstrap) return <div className="loading-screen"><div className="brand-symbol"><Icon name="lock"/></div><span>Loading workspace…</span></div>;
  if (inviteToken) return <InviteAcceptance token={inviteToken} onAccepted={async () => { cancelInvite(); await refreshBootstrap(); }} onCancel={cancelInvite}/>;
  if (!bootstrap.workspaces.length) return <EmptyWorkspace onCreated={refreshBootstrap}/>;
  return <Dashboard bootstrap={bootstrap}/>;
}
