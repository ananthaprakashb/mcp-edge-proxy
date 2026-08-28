const base = (process.env.CONTEXTGATEWAY_BASE_URL || "").replace(/\/$/, "");
const gatewayId = process.env.GATEWAY_ID || "";
const agentKey = process.env.AGENT_KEY || "";
const method = process.env.MCP_METHOD || "tools/call";
const name = process.env.MCP_NAME || "demo.allowed";

if (!base || !gatewayId || !agentKey) {
  console.error("Set CONTEXTGATEWAY_BASE_URL, GATEWAY_ID, and AGENT_KEY before running this smoke test.");
  process.exit(2);
}

const endpoint = `${base}/v1/mcp/${encodeURIComponent(gatewayId)}`;
const capabilityEndpoint = `${endpoint}/capabilities`;
const argumentsValue = { message: "phase-4-private-access-smoke" };

async function read(response) {
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { response, data };
}

const minted = await read(await fetch(capabilityEndpoint, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${agentKey}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ method, name, ttlSeconds: 30, arguments: argumentsValue }),
}));
if (minted.response.status !== 201 || !minted.data?.access_token) {
  throw new Error(`Capability mint failed: HTTP ${minted.response.status} ${JSON.stringify(minted.data)}`);
}
console.log("✓ capability minted for private gateway");

const result = await read(await fetch(endpoint, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${minted.data.access_token}`,
    "Content-Type": "application/json",
    "Mcp-Method": method,
    "Mcp-Name": name,
  },
  body: JSON.stringify({
    jsonrpc: "2.0",
    id: crypto.randomUUID(),
    method,
    params: { name, arguments: argumentsValue },
  }),
}));

if (result.response.status < 200 || result.response.status >= 300) {
  throw new Error(`Private upstream execution failed: HTTP ${result.response.status} ${JSON.stringify(result.data)}`);
}
if (result.response.headers.get("x-contextgateway-upstream-mode") !== "cloudflare_access") {
  throw new Error(`Expected X-ContextGateway-Upstream-Mode=cloudflare_access, got ${result.response.headers.get("x-contextgateway-upstream-mode")}`);
}
if (result.response.headers.get("x-contextgateway-auth-mode") !== "capability") {
  throw new Error(`Expected capability auth mode, got ${result.response.headers.get("x-contextgateway-auth-mode")}`);
}

console.log(`✓ Access-protected Tunnel upstream reached: HTTP ${result.response.status}`);
console.log("✓ response confirms cloudflare_access upstream mode");
console.log("✓ execution used a short-lived capability");
console.log("PASS: Phase 4 private MCP connectivity works through Cloudflare Tunnel + Access.");
