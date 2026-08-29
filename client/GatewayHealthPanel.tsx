import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api";

type WorkspaceRole = "owner" | "admin" | "member";
type HealthStatus = "unknown" | "healthy" | "degraded" | "unreachable" | "auth_failure" | "dns_blocked" | "timeout" | "tls_failure";

type Gateway = {
  id: string;
  name: string;
  upstream_url: string;
  connection_mode: "public" | "cloudflare_access";
  enabled: number;
  health_status: HealthStatus;
  health_reason: string | null;
  last_health_checked_at: string | null;
  last_health_success_at: string | null;
  last_health_failure_at: string | null;
  last_health_latency_ms: number | null;
  last_health_http_status: number | null;
  consecutive_health_failures: number;
};

type HealthHistory = {
  id: string;
  trigger_type: "scheduled" | "manual";
  status: Exclude<HealthStatus, "unknown">;
  reason: string;
  connection_mode: "public" | "cloudflare_access";
  http_status: number | null;
  latency_ms: number | null;
  dns_addresses_json: string;
  checked_at: string;
};

type Props = {
  workspace: { id: string; role: WorkspaceRole };
};

function utcDate(value: string | null): string {
  if (!value) return "Never";
  const normalized = value.includes("T") ? value : value.replace(" ", "T");
  return new Date(normalized.endsWith("Z") ? normalized : `${normalized}Z`).toLocaleString();
}

function statusLabel(status: HealthStatus): string {
  const labels: Record<HealthStatus, string> = {
    unknown: "Not checked",
    healthy: "Healthy",
    degraded: "Degraded",
    unreachable: "Unreachable",
    auth_failure: "Auth failure",
    dns_blocked: "DNS blocked",
    timeout: "Timeout",
    tls_failure: "TLS failure",
  };
  return labels[status];
}

function badgeClass(status: HealthStatus): string {
  if (status === "healthy") return "badge good";
  if (status === "unknown") return "badge";
  if (status === "degraded") return "badge warn";
  return "badge bad";
}

function parseAddresses(raw: string): string[] {
  try {
    const value = JSON.parse(raw) as unknown;
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

export function GatewayHealthPanel({ workspace }: Props) {
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [history, setHistory] = useState<Record<string, HealthHistory[]>>({});
  const [expanded, setExpanded] = useState<string | null>(null);
  const [checking, setChecking] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const manager = workspace.role === "owner" || workspace.role === "admin";

  const loadGateways = useCallback(async () => {
    const data = await api<{ gateways: Gateway[] }>(`/v1/app/workspaces/${workspace.id}/gateways`);
    setGateways(data.gateways);
  }, [workspace.id]);

  useEffect(() => {
    setHistory({});
    setExpanded(null);
    void loadGateways().catch((e: unknown) => setError(e instanceof Error ? e.message : "Could not load gateway health"));
  }, [loadGateways]);

  const summary = useMemo(() => ({
    healthy: gateways.filter((gateway) => gateway.health_status === "healthy").length,
    unhealthy: gateways.filter((gateway) => !["healthy", "unknown"].includes(gateway.health_status)).length,
    unknown: gateways.filter((gateway) => gateway.health_status === "unknown").length,
  }), [gateways]);

  async function loadDetails(gatewayId: string) {
    setError("");
    try {
      const data = await api<{ history: HealthHistory[] }>(`/v1/app/workspaces/${workspace.id}/gateways/${gatewayId}/health`);
      setHistory((current) => ({ ...current, [gatewayId]: data.history }));
      setExpanded((current) => current === gatewayId ? null : gatewayId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load gateway diagnostics");
    }
  }

  async function check(gatewayId: string) {
    setChecking(gatewayId); setError(""); setNotice("");
    try {
      const data = await api<{ result: { status: HealthStatus; reason: string; latencyMs: number | null; httpStatus: number | null } }>(`/v1/app/workspaces/${workspace.id}/gateways/${gatewayId}/health/check`, { method: "POST" });
      setNotice(`Gateway check completed: ${statusLabel(data.result.status)} · ${data.result.reason}`);
      await loadGateways();
      const details = await api<{ history: HealthHistory[] }>(`/v1/app/workspaces/${workspace.id}/gateways/${gatewayId}/health`);
      setHistory((current) => ({ ...current, [gatewayId]: details.history }));
      setExpanded(gatewayId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not test gateway connection");
    } finally {
      setChecking(null);
    }
  }

  return <section>
    <div className="panel">
      <div className="panel-head"><div><h3>Gateway health & diagnostics</h3><p>Connectivity probes use DNS/SSRF validation and an authenticated HEAD request. They never execute MCP tools, count against MCP quota, or retain response bodies.</p></div><button onClick={() => loadGateways()}>Refresh</button></div>
      {error && <div className="error-banner">{error}<button onClick={() => setError("")}>×</button></div>}
      {notice && <div className="success-banner">{notice}<button onClick={() => setNotice("")}>×</button></div>}
      <div className="metrics">
        <div className="metric-card"><span>Healthy</span><strong>{summary.healthy}</strong></div>
        <div className="metric-card"><span>Needs attention</span><strong>{summary.unhealthy}</strong></div>
        <div className="metric-card"><span>Not checked</span><strong>{summary.unknown}</strong></div>
        <div className="metric-card"><span>Enabled gateways</span><strong>{gateways.filter((gateway) => gateway.enabled).length}</strong></div>
      </div>
    </div>

    <div className="gateway-grid">
      {gateways.map((gateway) => <article className="gateway-card" key={gateway.id}>
        <div className="gateway-title"><div><h3>{gateway.name}</h3><p>{gateway.connection_mode === "cloudflare_access" ? "Tunnel + Access" : "Public HTTPS"}</p></div><span className={badgeClass(gateway.health_status)}>{statusLabel(gateway.health_status)}</span></div>
        <div className="upstream"><span>Upstream</span><code>{gateway.upstream_url}</code></div>
        <div className="gateway-meta">
          <span>Last check: {utcDate(gateway.last_health_checked_at)}</span>
          <span>Latency: {gateway.last_health_latency_ms === null ? "—" : `${gateway.last_health_latency_ms} ms`}</span>
          <span>HTTP: {gateway.last_health_http_status ?? "—"}</span>
          <span>Failures: {gateway.consecutive_health_failures || 0}</span>
        </div>
        {gateway.health_reason && <p className="fine-print">Reason: <code>{gateway.health_reason}</code></p>}
        <div className="card-actions">
          <button onClick={() => loadDetails(gateway.id)}>{expanded === gateway.id ? "Hide diagnostics" : "Diagnostics"}</button>
          {manager && gateway.enabled === 1 && <button className="primary-subtle" disabled={checking === gateway.id} onClick={() => check(gateway.id)}>{checking === gateway.id ? "Testing…" : "Test connection"}</button>}
        </div>
        {expanded === gateway.id && <div className="key-list">
          {!history[gateway.id]?.length ? <div className="table-empty">No health checks recorded yet.</div> : history[gateway.id].map((item) => {
            const addresses = parseAddresses(item.dns_addresses_json);
            return <div className="key-row" key={item.id}><div><strong>{statusLabel(item.status)}</strong><small>{item.trigger_type} · {utcDate(item.checked_at)}</small><small>{item.reason}</small>{addresses.length > 0 && <small>DNS: {addresses.join(", ")}</small>}</div><div className="key-controls"><span className={badgeClass(item.status)}>{item.http_status ?? "no HTTP"}</span><small>{item.latency_ms === null ? "—" : `${item.latency_ms} ms`}</small></div></div>;
          })}
        </div>}
      </article>)}
    </div>
    {!gateways.length && <div className="panel empty-panel">No gateways are available for health checks yet.</div>}
  </section>;
}
