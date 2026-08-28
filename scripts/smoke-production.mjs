const baseUrl = (process.env.CONTEXTGATEWAY_URL || "").replace(/\/+$/, "");
const controlToken = process.env.CONTROL_PLANE_TOKEN || "";

if (!baseUrl) {
  console.error("CONTEXTGATEWAY_URL is required");
  process.exit(1);
}

if (!controlToken) {
  console.error("CONTROL_PLANE_TOKEN is required");
  process.exit(1);
}

const controlHeaders = {
  Authorization: `Bearer ${controlToken}`,
  "Content-Type": "application/json",
};

async function readJson(response) {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

async function expectJson(response, expectedStatus, label) {
  const body = await readJson(response);
  if (response.status !== expectedStatus) {
    const safeBody = body && typeof body === "object" ? JSON.stringify(body) : String(body ?? "");
    throw new Error(`${label} failed: expected HTTP ${expectedStatus}, got ${response.status}: ${safeBody}`);
  }
  return body;
}

async function postControl(path, payload, expectedStatus = 201) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: controlHeaders,
    body: JSON.stringify(payload),
  });
  return expectJson(response, expectedStatus, path);
}

async function getControl(path) {
  const response = await fetch(`${baseUrl}${path}`, {
    headers: { Authorization: `Bearer ${controlToken}` },
  });
  return expectJson(response, 200, path);
}

async function pollForTraceDecisions(gatewayId, expectedDecisions) {
  for (let attempt = 1; attempt <= 10; attempt += 1) {
    const payload = await getControl(`/v1/control/traces?gatewayId=${encodeURIComponent(gatewayId)}&limit=20`);
    const traces = Array.isArray(payload?.traces) ? payload.traces : [];
    const decisions = new Set(traces.map((trace) => trace?.decision));
    if (expectedDecisions.every((decision) => decisions.has(decision))) {
      return traces;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`Timed out waiting for trace decisions: ${expectedDecisions.join(", ")}`);
}

async function main() {
  console.log(`ContextGateway production smoke test: ${baseUrl}`);

  const healthResponse = await fetch(`${baseUrl}/healthz`);
  const health = await expectJson(healthResponse, 200, "health check");
  if (health?.status !== "ok") {
    throw new Error("health check returned HTTP 200 but did not report status=ok");
  }
  console.log("✓ health check");

  const timestamp = new Date().toISOString();
  const account = await postControl("/v1/control/accounts", {
    name: `ContextGateway Smoke ${timestamp}`,
    plan: "free",
  });
  console.log(`✓ account created: ${account.id}`);

  const gateway = await postControl("/v1/control/gateways", {
    accountId: account.id,
    name: "production-smoke",
    upstreamUrl: "https://httpbin.org/anything",
  });
  console.log(`✓ gateway created: ${gateway.id}`);

  const issuedKey = await postControl("/v1/control/keys", {
    accountId: account.id,
    gatewayId: gateway.id,
    name: "smoke-agent",
    allowedMethods: ["tools/call"],
    allowedNames: ["demo.allowed"],
  });
  const agentKey = issuedKey.key;
  if (typeof agentKey !== "string" || !agentKey.startsWith("cg_live_")) {
    throw new Error("agent key issuance did not return the expected cg_live_* credential");
  }
  console.log(`✓ scoped agent key issued: ${issuedKey.id}`);

  const allowedResponse = await fetch(`${baseUrl}/v1/mcp/${encodeURIComponent(gateway.id)}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${agentKey}`,
      "Content-Type": "application/json",
      "Mcp-Method": "tools/call",
      "Mcp-Name": "demo.allowed",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "demo.allowed", arguments: { message: "non-sensitive smoke test" } },
    }),
  });
  if (!allowedResponse.ok) {
    const body = await readJson(allowedResponse);
    throw new Error(`allowed MCP call failed with HTTP ${allowedResponse.status}: ${JSON.stringify(body)}`);
  }
  await allowedResponse.arrayBuffer();
  console.log(`✓ allowed tool call forwarded: HTTP ${allowedResponse.status}`);

  const deniedResponse = await fetch(`${baseUrl}/v1/mcp/${encodeURIComponent(gateway.id)}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${agentKey}`,
      "Content-Type": "application/json",
      "Mcp-Method": "tools/call",
      "Mcp-Name": "demo.denied",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "demo.denied", arguments: {} },
    }),
  });
  const deniedBody = await expectJson(deniedResponse, 403, "denied MCP call");
  if (deniedBody?.error?.code !== "policy_denied") {
    throw new Error("denied MCP call returned HTTP 403 without policy_denied error code");
  }
  console.log("✓ denied tool call blocked before forwarding: HTTP 403");

  const traces = await pollForTraceDecisions(gateway.id, ["allowed", "policy_denied"]);
  const smokeTraces = traces.filter((trace) => trace.gateway_id === gateway.id || trace.gatewayId === gateway.id);
  console.log(`✓ audit traces observed: ${smokeTraces.length || traces.length}`);

  console.log("\nPASS: production data plane, policy enforcement, and D1 trace path are working.");
  console.log("Disposable validation records were intentionally left in D1 for inspection.");
  console.log(`account_id=${account.id}`);
  console.log(`gateway_id=${gateway.id}`);
  console.log(`api_key_id=${issuedKey.id}`);
}

main().catch((error) => {
  console.error(`\nFAIL: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
