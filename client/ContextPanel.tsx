import { useCallback, useEffect, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import { api } from "./api";

type WorkspaceRole = "owner" | "admin" | "member";
type DocumentFormat = "json" | "yaml" | "markdown" | "text" | "okf";

type Gateway = { id: string; name: string; enabled: number };
type DocumentSummary = {
  id: string;
  documentKey: string;
  title: string;
  format: DocumentFormat;
  schemaName: string | null;
  schemaVersion: string | null;
  sourceLabel: string | null;
  version: number;
  contentHash: string;
  byteSize: number;
  effectiveAt: string | null;
  expiresAt: string | null;
  createdAt: string;
  policyCount: number;
};

type Policy = {
  id: string;
  document_key: string;
  gateway_id: string | null;
  api_key_id: string | null;
  allowed_paths_json: string;
  allowed_operations_json: string;
  created_at: string;
};

type AccessRow = {
  id: string;
  document_version: number;
  content_hash: string;
  gateway_name: string;
  api_key_name: string | null;
  operation: "read" | "list";
  requested_path: string | null;
  decision: "allowed" | "denied";
  reason: string;
  capability_jti: string | null;
  created_at: string;
};

type Props = { workspace: { id: string; role: WorkspaceRole } };

function shortHash(value: string) { return `${value.slice(0, 12)}…`; }
function parsePaths(value: string) { return value.split(",").map((item) => item.trim()).filter(Boolean); }
function localTime(value: string) { return new Date(value.endsWith("Z") ? value : `${value.replace(" ", "T")}Z`).toLocaleString(); }

export function ContextPanel({ workspace }: Props) {
  const [documents, setDocuments] = useState<DocumentSummary[]>([]);
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [title, setTitle] = useState("");
  const [documentKey, setDocumentKey] = useState("");
  const [format, setFormat] = useState<DocumentFormat>("json");
  const [content, setContent] = useState("");
  const [schemaName, setSchemaName] = useState("");
  const [schemaVersion, setSchemaVersion] = useState("");
  const [sourceLabel, setSourceLabel] = useState("");
  const [effectiveAt, setEffectiveAt] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [gatewayId, setGatewayId] = useState("");
  const [allowedPaths, setAllowedPaths] = useState("*");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [access, setAccess] = useState<AccessRow[]>([]);
  const [validation, setValidation] = useState<string>("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const manager = workspace.role === "owner" || workspace.role === "admin";

  const load = useCallback(async () => {
    const [docs, gatewayData] = await Promise.all([
      api<{ documents: DocumentSummary[] }>(`/v1/app/workspaces/${workspace.id}/documents`),
      api<{ gateways: Gateway[] }>(`/v1/app/workspaces/${workspace.id}/gateways`),
    ]);
    setDocuments(docs.documents);
    setGateways(gatewayData.gateways);
    if (!gatewayId && gatewayData.gateways[0]) setGatewayId(gatewayData.gateways[0].id);
  }, [workspace.id, gatewayId]);

  useEffect(() => { void load().catch((e: unknown) => setError(e instanceof Error ? e.message : "Could not load governed context")); }, [load]);

  async function loadPolicies(key: string) {
    const [policyData, accessData] = await Promise.all([
      api<{ policies: Policy[] }>(`/v1/app/workspaces/${workspace.id}/documents/${encodeURIComponent(key)}/policies`),
      api<{ access: AccessRow[] }>(`/v1/app/workspaces/${workspace.id}/documents/${encodeURIComponent(key)}/access?limit=50`),
    ]);
    setSelectedKey(key);
    setPolicies(policyData.policies);
    setAccess(accessData.access);
  }

  async function validate() {
    setError(""); setValidation("");
    try {
      const result = await api<{ contentHash: string; byteSize: number; topLevelKeys: string[] }>(`/v1/app/workspaces/${workspace.id}/documents/validate`, {
        method: "POST",
        body: JSON.stringify({ format, content }),
      });
      setValidation(`Valid · ${result.byteSize.toLocaleString()} bytes · SHA-256 ${shortHash(result.contentHash)}${result.topLevelKeys.length ? ` · keys: ${result.topLevelKeys.slice(0, 6).join(", ")}` : ""}`);
    } catch (e) { setError(e instanceof Error ? e.message : "Validation failed"); }
  }

  async function ingest(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(""); setNotice("");
    try {
      await api(`/v1/app/workspaces/${workspace.id}/documents`, {
        method: "POST",
        body: JSON.stringify({
          title,
          documentKey,
          format,
          content,
          schemaName: schemaName || undefined,
          schemaVersion: schemaVersion || undefined,
          sourceLabel: sourceLabel || undefined,
          effectiveAt: effectiveAt || undefined,
          expiresAt: expiresAt || undefined,
          ...(gatewayId ? { policy: { gatewayId, allowedPaths: parsePaths(allowedPaths), allowedOperations: ["read", "list"] } } : {}),
        }),
      });
      setNotice("Document ingested. A new version supersedes the prior active version for the same document key.");
      setContent(""); setValidation("");
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not ingest document"); }
    finally { setBusy(false); }
  }

  async function fileSelected(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > 256 * 1024) { setError("Document exceeds the 256 KiB Phase 10 limit."); return; }
    setContent(await file.text());
    if (!title) setTitle(file.name);
    if (!documentKey) setDocumentKey(file.name.toLowerCase().replace(/\.[^.]+$/, "").replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 96));
    const ext = file.name.split(".").pop()?.toLowerCase();
    if (ext === "yaml" || ext === "yml") setFormat("yaml");
    else if (ext === "md" || ext === "markdown") setFormat("markdown");
    else if (ext === "txt") setFormat("text");
    else if (ext === "json") setFormat("json");
  }

  async function grantPolicy(event: FormEvent) {
    event.preventDefault();
    if (!selectedKey || !gatewayId) return;
    setBusy(true); setError("");
    try {
      await api(`/v1/app/workspaces/${workspace.id}/documents/${encodeURIComponent(selectedKey)}/policies`, {
        method: "POST",
        body: JSON.stringify({ gatewayId, allowedPaths: parsePaths(allowedPaths), allowedOperations: ["read", "list"] }),
      });
      setNotice("Document access policy granted.");
      await Promise.all([loadPolicies(selectedKey), load()]);
    } catch (e) { setError(e instanceof Error ? e.message : "Could not grant document policy"); }
    finally { setBusy(false); }
  }

  async function revokePolicy(policyId: string) {
    if (!selectedKey || !confirm("Revoke this governed document access policy?")) return;
    await api(`/v1/app/workspaces/${workspace.id}/documents/${encodeURIComponent(selectedKey)}/policies/${policyId}`, { method: "DELETE" });
    setNotice("Document access policy revoked.");
    await Promise.all([loadPolicies(selectedKey), load()]);
  }

  return <section>
    <div className="panel">
      <div className="panel-head"><div><h3>Governed context</h3><p>Ingest versioned JSON, YAML, Markdown, text, or OKF-style content and expose only policy-authorized fields through capability-bound MCP tools.</p></div><button onClick={() => load()}>Refresh</button></div>
      {error && <div className="error-banner">{error}<button onClick={() => setError("")}>×</button></div>}
      {notice && <div className="success-banner">{notice}<button onClick={() => setNotice("")}>×</button></div>}
      <p className="fine-print">Phase 10 storage is capped at 256 KiB per document. Raw document content is never forwarded to the configured upstream MCP server by ContextGateway's built-in document tools.</p>
    </div>

    {manager && <div className="panel">
      <div className="panel-head"><div><h3>Ingest document</h3><p>Exact duplicate content is rejected. Reusing a document key with changed content creates the next version and supersedes the previous active version.</p></div></div>
      <form onSubmit={ingest}>
        <div className="filters"><input placeholder="Document key · employee-handbook" value={documentKey} onChange={(e) => setDocumentKey(e.target.value)} required /><input placeholder="Title" value={title} onChange={(e) => setTitle(e.target.value)} required /><select value={format} onChange={(e) => setFormat(e.target.value as DocumentFormat)}><option value="json">JSON</option><option value="yaml">YAML</option><option value="markdown">Markdown</option><option value="text">Text</option><option value="okf">OKF-style</option></select></div>
        <div className="filters"><input placeholder="Schema name · optional" value={schemaName} onChange={(e) => setSchemaName(e.target.value)} /><input placeholder="Schema version · optional" value={schemaVersion} onChange={(e) => setSchemaVersion(e.target.value)} /><input placeholder="Source / provenance label · optional" value={sourceLabel} onChange={(e) => setSourceLabel(e.target.value)} /></div>
        <div className="filters"><label>Effective at <input type="datetime-local" value={effectiveAt} onChange={(e) => setEffectiveAt(e.target.value)} /></label><label>Expires at <input type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} /></label><label>Load local text document <input type="file" accept=".json,.yaml,.yml,.md,.markdown,.txt,text/plain,application/json" onChange={(e) => void fileSelected(e)} /></label></div>
        <label>Content<textarea rows={10} value={content} onChange={(e) => setContent(e.target.value)} required placeholder='{"public":{"message":"hello"},"private":{"secret":"not exposed"}}' /></label>
        <div className="filters"><select value={gatewayId} onChange={(e) => setGatewayId(e.target.value)}><option value="">No initial gateway policy</option>{gateways.map((gateway) => <option key={gateway.id} value={gateway.id}>{gateway.name}</option>)}</select><input value={allowedPaths} onChange={(e) => setAllowedPaths(e.target.value)} placeholder="Allowed paths: * or /public/*" /><button type="button" onClick={() => void validate()}>Validate</button><button className="primary" disabled={busy}>{busy ? "Ingesting…" : "Ingest"}</button></div>
        {validation && <div className="success-banner">{validation}</div>}
      </form>
    </div>}

    <div className="panel">
      <div className="panel-head"><div><h3>Documents</h3><p>Only metadata is shown here. Content is returned to agents only after capability and document-policy enforcement.</p></div></div>
      {!documents.length ? <div className="table-empty">No governed context documents yet.</div> : <div className="table-wrap"><table><thead><tr><th>Document</th><th>Version</th><th>Format/schema</th><th>Provenance</th><th>Validity</th><th>Policies</th><th>Hash</th><th>Action</th></tr></thead><tbody>{documents.map((doc) => <tr key={doc.id}><td><strong>{doc.title}</strong><small>{doc.documentKey}</small></td><td>v{doc.version}</td><td>{doc.format}<small>{doc.schemaName ? `${doc.schemaName}${doc.schemaVersion ? ` · ${doc.schemaVersion}` : ""}` : "—"}</small></td><td>{doc.sourceLabel || "—"}<small>{doc.byteSize.toLocaleString()} bytes</small></td><td><small>{doc.effectiveAt ? `from ${localTime(doc.effectiveAt)}` : "effective now"}</small><small>{doc.expiresAt ? `until ${localTime(doc.expiresAt)}` : "no expiry"}</small></td><td>{doc.policyCount}</td><td><code title={doc.contentHash}>{shortHash(doc.contentHash)}</code></td><td><button onClick={() => void loadPolicies(doc.documentKey)}>Policies & access</button></td></tr>)}</tbody></table></div>}
    </div>

    {selectedKey && <>
      <div className="panel">
        <div className="panel-head"><div><h3>Access policies · {selectedKey}</h3><p>Gateway-wide policies may be narrowed to exact JSON-pointer-style paths. The API also supports optional agent-key-specific policies.</p></div><button onClick={() => setSelectedKey(null)}>Close</button></div>
        {manager && <form className="filters" onSubmit={grantPolicy}><select value={gatewayId} onChange={(e) => setGatewayId(e.target.value)} required>{gateways.map((gateway) => <option key={gateway.id} value={gateway.id}>{gateway.name}</option>)}</select><input value={allowedPaths} onChange={(e) => setAllowedPaths(e.target.value)} placeholder="*, /public/*, /sections/benefits" /><button className="primary-subtle" disabled={busy}>Grant access</button></form>}
        {!policies.length ? <div className="table-empty">No access policy. This document is fail-closed and cannot be retrieved by an agent.</div> : <div className="table-wrap"><table><thead><tr><th>Gateway</th><th>Agent key</th><th>Paths</th><th>Operations</th><th>Action</th></tr></thead><tbody>{policies.map((policy) => <tr key={policy.id}><td>{policy.gateway_id || "Any gateway"}</td><td>{policy.api_key_id || "Any key"}</td><td><code>{policy.allowed_paths_json}</code></td><td><code>{policy.allowed_operations_json}</code></td><td>{manager ? <button className="danger-link" onClick={() => void revokePolicy(policy.id)}>Revoke</button> : "—"}</td></tr>)}</tbody></table></div>}
        <p className="fine-print">Agent keys must allow <code>tools/call</code> with names <code>contextgateway.document.list</code> and/or <code>contextgateway.document.read</code>. Reads additionally require an arguments-bound <code>cg_cap_*</code> capability.</p>
      </div>
      <div className="panel">
        <div className="panel-head"><div><h3>Recent document access</h3><p>Audit metadata only—no returned document content is stored in this log.</p></div><button onClick={() => void loadPolicies(selectedKey)}>Refresh</button></div>
        {!access.length ? <div className="table-empty">No governed MCP access recorded for this document yet.</div> : <div className="table-wrap"><table><thead><tr><th>Decision</th><th>Operation/path</th><th>Gateway/key</th><th>Version/hash</th><th>Reason</th><th>Capability</th><th>Time</th></tr></thead><tbody>{access.map((row) => <tr key={row.id}><td><span className={`badge ${row.decision === "allowed" ? "good" : "bad"}`}>{row.decision}</span></td><td>{row.operation}<small>{row.requested_path || "full/list"}</small></td><td>{row.gateway_name}<small>{row.api_key_name || "—"}</small></td><td>v{row.document_version}<small><code>{shortHash(row.content_hash)}</code></small></td><td>{row.reason}</td><td><code>{row.capability_jti ? `${row.capability_jti.slice(0, 10)}…` : "—"}</code></td><td>{localTime(row.created_at)}</td></tr>)}</tbody></table></div>}
      </div>
    </>}
  </section>;
}
