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
const args = { message: "phase-3b-capability-required-smoke" };

async function parse(response) {
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { response, data };
}

function requestBody(argumentsValue = args) {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: crypto.randomUUID(),
    method,
    params: { name, arguments: argumentsValue },
  });
}

const direct = await parse(await fetch(endpoint, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${agentKey}`,
    "Content-Type": "application/json",
    "Mcp-Method": method,
    "Mcp-Name": name,
  },
  body: requestBody(),
}));
if (direct.response.status !== 403 || direct.data?.error?.code !== "capability_required") {
  throw new Error(`Direct key bypass was not blocked. Set this key to capability_required first. HTTP ${direct.response.status} ${JSON.stringify(direct.data)}`);
}
console.log("✓ direct cg_live_* execution blocked: HTTP 403 capability_required");

const minted = await parse(await fetch(capabilityEndpoint, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${agentKey}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ method, name, ttlSeconds: 30, arguments: args }),
}));
if (minted.response.status !== 201 || !minted.data?.access_token) {
  throw new Error(`Capability mint failed: HTTP ${minted.response.status} ${JSON.stringify(minted.data)}`);
}
console.log("✓ the same cg_live_* key can still mint a short-lived capability");

const capability = await parse(await fetch(endpoint, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${minted.data.access_token}`,
    "Content-Type": "application/json",
    "Mcp-Method": method,
    "Mcp-Name": name,
  },
  body: requestBody(),
}));
if (capability.response.status < 200 || capability.response.status >= 300) {
  throw new Error(`Capability execution failed: HTTP ${capability.response.status} ${JSON.stringify(capability.data)}`);
}
if (capability.response.headers.get("x-contextgateway-auth-mode") !== "capability") {
  throw new Error("Successful response did not identify capability auth mode");
}
if (capability.response.headers.get("x-contextgateway-execution-mode") !== "capability_required") {
  throw new Error("Successful response did not identify capability_required execution mode");
}
console.log(`✓ cg_cap_* execution allowed: HTTP ${capability.response.status}`);
console.log("✓ response confirms capability + capability_required enforcement");

const replay = await parse(await fetch(endpoint, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${minted.data.access_token}`,
    "Content-Type": "application/json",
    "Mcp-Method": method,
    "Mcp-Name": name,
  },
  body: requestBody(),
}));
if (replay.response.status !== 401 || replay.data?.error?.code !== "capability_replayed") {
  throw new Error(`Capability replay was not blocked: HTTP ${replay.response.status} ${JSON.stringify(replay.data)}`);
}
console.log("✓ capability remains single-use: HTTP 401 capability_replayed");

console.log("PASS: capability-required keys cannot bypass the exchange, while minted single-use capabilities execute normally.");
