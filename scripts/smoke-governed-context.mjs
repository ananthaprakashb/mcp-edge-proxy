const base = (process.env.CONTEXTGATEWAY_BASE_URL || "").replace(/\/$/, "");
const gatewayId = process.env.GATEWAY_ID || "";
const agentKey = process.env.AGENT_KEY || "";
const documentKey = process.env.CONTEXT_DOCUMENT_KEY || "";
const documentPath = process.env.CONTEXT_DOCUMENT_PATH || "";

if (!base || !gatewayId || !agentKey || !documentKey) {
  console.error("Set CONTEXTGATEWAY_BASE_URL, GATEWAY_ID, AGENT_KEY, and CONTEXT_DOCUMENT_KEY before running this smoke test.");
  process.exit(2);
}

const endpoint = `${base}/v1/mcp/${encodeURIComponent(gatewayId)}`;
const capabilityEndpoint = `${endpoint}/capabilities`;
const name = "contextgateway.document.read";
const args = { documentKey, ...(documentPath ? { path: documentPath } : {}) };
const rpc = () => JSON.stringify({ jsonrpc: "2.0", id: crypto.randomUUID(), method: "tools/call", params: { name, arguments: args } });

async function parse(response) {
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { response, data };
}

const direct = await parse(await fetch(endpoint, {
  method: "POST",
  headers: { Authorization: `Bearer ${agentKey}`, "Content-Type": "application/json" },
  body: rpc(),
}));
if (direct.response.status !== 403 || direct.data?.error?.code !== "context_capability_required") {
  throw new Error(`Governed context accepted a long-lived key directly: HTTP ${direct.response.status} ${JSON.stringify(direct.data)}`);
}
console.log("✓ governed document reads reject direct cg_live_* execution");

const unbound = await parse(await fetch(capabilityEndpoint, {
  method: "POST",
  headers: { Authorization: `Bearer ${agentKey}`, "Content-Type": "application/json" },
  body: JSON.stringify({ method: "tools/call", name, ttlSeconds: 30 }),
}));
if (unbound.response.status !== 201 || !unbound.data?.access_token) {
  throw new Error(`Unbound capability mint failed; ensure the key policy allows ${name}: HTTP ${unbound.response.status} ${JSON.stringify(unbound.data)}`);
}
const unboundRead = await parse(await fetch(endpoint, {
  method: "POST",
  headers: { Authorization: `Bearer ${unbound.data.access_token}`, "Content-Type": "application/json" },
  body: rpc(),
}));
if (unboundRead.response.status !== 403 || unboundRead.data?.error?.code !== "context_arguments_binding_required") {
  throw new Error(`Unbound document capability was not rejected: HTTP ${unboundRead.response.status} ${JSON.stringify(unboundRead.data)}`);
}
console.log("✓ generic/unbound capabilities cannot read governed documents");

const minted = await parse(await fetch(capabilityEndpoint, {
  method: "POST",
  headers: { Authorization: `Bearer ${agentKey}`, "Content-Type": "application/json" },
  body: JSON.stringify({ method: "tools/call", name, ttlSeconds: 30, arguments: args }),
}));
if (minted.response.status !== 201 || !minted.data?.access_token) {
  throw new Error(`Bound capability mint failed: HTTP ${minted.response.status} ${JSON.stringify(minted.data)}`);
}
console.log("✓ exact documentKey/path capability minted");

const read = await parse(await fetch(endpoint, {
  method: "POST",
  headers: { Authorization: `Bearer ${minted.data.access_token}`, "Content-Type": "application/json" },
  body: rpc(),
}));
if (!read.response.ok || read.data?.result?.structuredContent?.documentKey !== documentKey) {
  throw new Error(`Governed context read failed: HTTP ${read.response.status} ${JSON.stringify(read.data)}`);
}
if (!read.data?.result?.structuredContent?.contentHash || !("value" in read.data.result.structuredContent)) {
  throw new Error("Governed context response did not include provenance hash and selected value");
}
console.log(`✓ governed context returned ${documentKey}${documentPath || " (full allowed document)"} with provenance hash`);

const replay = await parse(await fetch(endpoint, {
  method: "POST",
  headers: { Authorization: `Bearer ${minted.data.access_token}`, "Content-Type": "application/json" },
  body: rpc(),
}));
if (replay.response.status !== 401 || replay.data?.error?.code !== "capability_replayed") {
  throw new Error(`Governed context capability replay was not blocked: HTTP ${replay.response.status} ${JSON.stringify(replay.data)}`);
}
console.log("✓ governed context capability remains single-use");
console.log("PASS: document retrieval is capability-bound, policy-gated, provenance-tagged, and replay protected.");
