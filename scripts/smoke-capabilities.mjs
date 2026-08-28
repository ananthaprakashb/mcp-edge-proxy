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
const expectedArgs = { message: "phase-3-capability-smoke", sequence: 1 };

async function jsonResponse(response) {
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { response, data };
}

async function mint(argumentsValue = expectedArgs) {
  const result = await jsonResponse(await fetch(capabilityEndpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${agentKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ method, name, ttlSeconds: 30, arguments: argumentsValue }),
  }));
  if (result.response.status !== 201 || !result.data?.access_token) {
    throw new Error(`Capability mint failed: HTTP ${result.response.status} ${JSON.stringify(result.data)}`);
  }
  return result.data.access_token;
}

async function call(token, argumentsValue) {
  return jsonResponse(await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
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
}

const token = await mint();
console.log("✓ argument-bound capability minted");

const allowed = await call(token, expectedArgs);
if (allowed.response.status < 200 || allowed.response.status >= 300) {
  throw new Error(`Capability execution failed: HTTP ${allowed.response.status} ${JSON.stringify(allowed.data)}`);
}
console.log(`✓ capability executed once: HTTP ${allowed.response.status}`);

const replay = await call(token, expectedArgs);
if (replay.response.status !== 401 || replay.data?.error?.code !== "capability_replayed") {
  throw new Error(`Replay was not blocked correctly: HTTP ${replay.response.status} ${JSON.stringify(replay.data)}`);
}
console.log("✓ replay blocked: HTTP 401 capability_replayed");

const argumentToken = await mint();
const wrongArgs = await call(argumentToken, { ...expectedArgs, sequence: 999 });
if (wrongArgs.response.status !== 403 || wrongArgs.data?.error?.code !== "capability_arguments_denied") {
  throw new Error(`Argument mismatch was not blocked: HTTP ${wrongArgs.response.status} ${JSON.stringify(wrongArgs.data)}`);
}
console.log("✓ wrong arguments blocked without consuming capability: HTTP 403");

const correctAfterMismatch = await call(argumentToken, expectedArgs);
if (correctAfterMismatch.response.status < 200 || correctAfterMismatch.response.status >= 300) {
  throw new Error(`Capability was incorrectly consumed by argument mismatch: HTTP ${correctAfterMismatch.response.status} ${JSON.stringify(correctAfterMismatch.data)}`);
}
console.log(`✓ correct arguments still execute after denied mismatch: HTTP ${correctAfterMismatch.response.status}`);

const scopeToken = await mint();
const wrongScope = await jsonResponse(await fetch(endpoint, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${scopeToken}`,
    "Content-Type": "application/json",
    "Mcp-Method": method,
    "Mcp-Name": `${name}.wrong`,
  },
  body: JSON.stringify({
    jsonrpc: "2.0",
    id: crypto.randomUUID(),
    method,
    params: { name: `${name}.wrong`, arguments: expectedArgs },
  }),
}));
if (wrongScope.response.status !== 403 || wrongScope.data?.error?.code !== "capability_scope_denied") {
  throw new Error(`Scope mismatch was not blocked: HTTP ${wrongScope.response.status} ${JSON.stringify(wrongScope.data)}`);
}
console.log("✓ wrong tool scope blocked: HTTP 403");

console.log("PASS: Phase 3 short-lived, single-use, scope-bound, argument-bound capability flow works.");
