import {
  capabilityArgumentsMatch,
  consumeCapability,
  DEFAULT_CAPABILITY_TTL_SECONDS,
  isCapabilityToken,
  issueCapabilityToken,
  MAX_CAPABILITY_TTL_SECONDS,
  verifyCapabilityToken,
  type CapabilityClaims,
} from "./capability";
import { decryptString, encryptString, generateAgentKey, secureTokenEquals, sha256Hex } from "./crypto";
import {
  createAccount,
  createApiKey,
  createGateway,
  getApiKeyByIdForGateway,
  getApiKeyForGateway,
  getGateway,
  insertTrace,
  listTraces,
  revokeApiKey,
} from "./db";
import { extractMcpOperation } from "./mcp";
import { evaluatePolicy, normalizePolicyInput, parsePolicy } from "./policy";
import { buildUpstreamHeaders, validateUpstreamHeaders, validateUpstreamUrl } from "./security";
import { consumeMonthlyRequest } from "./usage";
import type {
  ApiKeyAuthRow,
  Env,
  ExecutionContextLike,
  Plan,
  SubscriptionStatus,
  TraceRecord,
  TraceSpan,
} from "./types";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

function json(data: unknown, status = 200, headers?: HeadersInit): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...headers },
  });
}

function errorResponse(status: number, code: string, message: string, requestId?: string): Response {
  return json({ error: { code, message, ...(requestId ? { requestId } : {}) } }, status);
}

function bearerToken(request: Request): string | null {
  const value = request.headers.get("authorization");
  if (!value) return null;
  const match = /^Bearer\s+(.+)$/i.exec(value);
  return match?.[1] ?? null;
}

async function readJsonObject(request: Request): Promise<Record<string, unknown>> {
  const body = (await request.json()) as unknown;
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("JSON request body must be an object");
  }
  return body as Record<string, unknown>;
}

function requiredString(body: Record<string, unknown>, field: string, maxLength = 300): string {
  const value = body[field];
  if (typeof value !== "string" || value.trim().length === 0 || value.length > maxLength) {
    throw new Error(`${field} must be a non-empty string no longer than ${maxLength} characters`);
  }
  return value.trim();
}

function optionalString(body: Record<string, unknown>, field: string, maxLength = 300): string | null {
  const value = body[field];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length > maxLength) {
    throw new Error(`${field} must be a string no longer than ${maxLength} characters`);
  }
  return value;
}

function optionalScopeName(body: Record<string, unknown>): string | null {
  const value = body.name;
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || !value.trim() || value.length > 300) {
    throw new Error("name must be null or a non-empty string no longer than 300 characters");
  }
  return value.trim();
}

function parseCapabilityTtl(value: unknown): number {
  if (value === undefined) return DEFAULT_CAPABILITY_TTL_SECONDS;
  if (!Number.isInteger(value) || Number(value) < 1 || Number(value) > MAX_CAPABILITY_TTL_SECONDS) {
    throw new Error(`ttlSeconds must be an integer between 1 and ${MAX_CAPABILITY_TTL_SECONDS}`);
  }
  return Number(value);
}

function parsePlan(value: unknown): Plan {
  if (value === undefined) return "free";
  if (value === "free" || value === "pro" || value === "team") return value;
  throw new Error("plan must be one of: free, pro, team");
}

function parseSubscriptionStatus(value: unknown, plan: Plan): SubscriptionStatus {
  if (plan === "free") return "free";
  if (value === undefined) return "trialing";
  if (value === "trialing" || value === "active" || value === "past_due" || value === "canceled") {
    return value;
  }
  throw new Error("subscriptionStatus must be one of: trialing, active, past_due, canceled");
}

function subscriptionAllowsTraffic(plan: Plan, status: SubscriptionStatus): boolean {
  return plan === "free" || status === "active" || status === "trialing";
}

function safeContentLength(headers: Headers): number | null {
  const raw = headers.get("content-length");
  if (!raw) return null;
  const value = Number(raw);
  return Number.isFinite(value) && value >= 0 ? value : null;
}

async function isControlPlaneAuthorized(request: Request, env: Env): Promise<boolean> {
  const token = bearerToken(request);
  if (!token || !env.CONTROL_PLANE_TOKEN) return false;
  return secureTokenEquals(token, env.CONTROL_PLANE_TOKEN);
}

async function handleControlPlane(request: Request, env: Env, path: string): Promise<Response> {
  if (!(await isControlPlaneAuthorized(request, env))) {
    return errorResponse(401, "unauthorized", "A valid control-plane bearer token is required");
  }

  try {
    if (request.method === "POST" && path === "/v1/control/accounts") {
      const body = await readJsonObject(request);
      const plan = parsePlan(body.plan);
      const subscriptionStatus = parseSubscriptionStatus(body.subscriptionStatus, plan);
      const account = {
        id: crypto.randomUUID(),
        name: requiredString(body, "name", 120),
        plan,
        subscription_status: subscriptionStatus,
      };
      await createAccount(env.DB, account);
      return json(
        {
          id: account.id,
          name: account.name,
          plan: account.plan,
          subscriptionStatus: account.subscription_status,
        },
        201,
      );
    }

    if (request.method === "POST" && path === "/v1/control/gateways") {
      const body = await readJsonObject(request);
      const accountId = requiredString(body, "accountId", 100);
      const upstreamUrl = requiredString(body, "upstreamUrl", 2048);
      const parsedUrl = validateUpstreamUrl(upstreamUrl, env.ALLOW_INSECURE_UPSTREAMS === "true");
      const upstreamHeaders = validateUpstreamHeaders(body.upstreamHeaders);

      const account = await env.DB
        .prepare("SELECT id FROM accounts WHERE id = ?")
        .bind(accountId)
        .first<{ id: string }>();
      if (!account) return errorResponse(404, "account_not_found", "Account not found");

      let ciphertext: string | null = null;
      let iv: string | null = null;
      if (Object.keys(upstreamHeaders).length > 0) {
        const encrypted = await encryptString(JSON.stringify(upstreamHeaders), env.UPSTREAM_ENCRYPTION_KEY);
        ciphertext = encrypted.ciphertext;
        iv = encrypted.iv;
      }

      const gateway = {
        id: crypto.randomUUID(),
        accountId,
        name: requiredString(body, "name", 120),
        upstreamUrl: parsedUrl.toString(),
        upstreamHeadersCiphertext: ciphertext,
        upstreamHeadersIv: iv,
      };
      await createGateway(env.DB, gateway);
      return json(
        {
          id: gateway.id,
          accountId: gateway.accountId,
          name: gateway.name,
          mcpEndpoint: `/v1/mcp/${gateway.id}`,
        },
        201,
      );
    }

    if (request.method === "POST" && path === "/v1/control/keys") {
      const body = await readJsonObject(request);
      const accountId = requiredString(body, "accountId", 100);
      const gatewayId = requiredString(body, "gatewayId", 100);
      const gateway = await getGateway(env.DB, gatewayId);
      if (!gateway || gateway.account_id !== accountId) {
        return errorResponse(404, "gateway_not_found", "Gateway not found for this account");
      }

      const allowedMethods = normalizePolicyInput(body.allowedMethods);
      const allowedNames = normalizePolicyInput(body.allowedNames);
      const secret = generateAgentKey();
      const key = {
        id: crypto.randomUUID(),
        accountId,
        gatewayId,
        name: requiredString(body, "name", 120),
        secretHash: await sha256Hex(secret),
        keyPrefix: secret.slice(0, 18),
        allowedMethods,
        allowedNames,
      };
      await createApiKey(env.DB, key);
      return json(
        {
          id: key.id,
          gatewayId,
          name: key.name,
          key: secret,
          keyPrefix: key.keyPrefix,
          allowedMethods,
          allowedNames,
          warning: "This key is returned only once. Store it securely.",
        },
        201,
      );
    }

    const keyDeleteMatch = /^\/v1\/control\/keys\/([^/]+)$/.exec(path);
    if (request.method === "DELETE" && keyDeleteMatch) {
      await revokeApiKey(env.DB, decodeURIComponent(keyDeleteMatch[1]));
      return new Response(null, { status: 204 });
    }

    if (request.method === "GET" && path === "/v1/control/traces") {
      const url = new URL(request.url);
      const gatewayId = url.searchParams.get("gatewayId");
      if (!gatewayId) throw new Error("gatewayId query parameter is required");
      const requestedLimit = Number(url.searchParams.get("limit") ?? "100");
      const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(250, Math.floor(requestedLimit))) : 100;
      return json({ traces: await listTraces(env.DB, gatewayId, limit) });
    }

    const subscriptionMatch = /^\/v1\/control\/accounts\/([^/]+)\/subscription$/.exec(path);
    if (request.method === "PATCH" && subscriptionMatch) {
      const body = await readJsonObject(request);
      const plan = parsePlan(body.plan);
      const status = parseSubscriptionStatus(body.subscriptionStatus, plan);
      const accountId = decodeURIComponent(subscriptionMatch[1]);
      await env.DB
        .prepare(
          `UPDATE accounts
           SET plan = ?, subscription_status = ?, billing_customer_id = ?, billing_subscription_id = ?
           WHERE id = ?`,
        )
        .bind(
          plan,
          status,
          optionalString(body, "billingCustomerId", 200),
          optionalString(body, "billingSubscriptionId", 200),
          accountId,
        )
        .run();
      return json({ accountId, plan, subscriptionStatus: status });
    }

    return errorResponse(404, "not_found", "Control-plane route not found");
  } catch (error) {
    return errorResponse(400, "invalid_request", error instanceof Error ? error.message : "Invalid request");
  }
}

function queueTrace(env: Env, ctx: ExecutionContextLike, trace: TraceRecord): void {
  ctx.waitUntil(
    insertTrace(env.DB, trace).catch(() => {
      // Tracing is deliberately best-effort; data-plane traffic is not failed by an audit write outage.
    }),
  );
}

function traceResult(
  env: Env,
  ctx: ExecutionContextLike,
  startedAt: number,
  base: Omit<TraceRecord, "id" | "durationMs" | "statusCode" | "decision" | "responseBytes">,
  decision: string,
  statusCode: number,
  responseBytes: number | null,
): void {
  queueTrace(env, ctx, {
    ...base,
    id: crypto.randomUUID(),
    decision,
    statusCode,
    durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
    responseBytes,
  });
}

function applySpanAttributes(
  span: TraceSpan | undefined,
  values: {
    gatewayId: string;
    method: string | null;
    name: string | null;
    decision?: string;
    statusCode?: number;
    authMode?: "agent_key" | "capability";
  },
): void {
  if (!span) return;
  span.setAttribute("contextgateway.gateway.id", values.gatewayId);
  span.setAttribute("mcp.method.name", values.method ?? undefined);
  span.setAttribute("mcp.name", values.name ?? undefined);
  span.setAttribute("contextgateway.policy.decision", values.decision);
  span.setAttribute("contextgateway.auth.mode", values.authMode);
  span.setAttribute("http.response.status_code", values.statusCode);
}

async function issueCapability(request: Request, env: Env, gatewayId: string): Promise<Response> {
  if (request.method !== "POST") return errorResponse(405, "method_not_allowed", "POST required");
  const gateway = await getGateway(env.DB, gatewayId);
  if (!gateway || gateway.enabled !== 1) return errorResponse(404, "gateway_not_found", "Gateway not found or disabled");

  const bootstrapToken = bearerToken(request);
  if (!bootstrapToken || isCapabilityToken(bootstrapToken)) {
    return errorResponse(401, "unauthorized", "A long-lived gateway agent key is required to mint capabilities");
  }
  const auth = await getApiKeyForGateway(env.DB, gatewayId, await sha256Hex(bootstrapToken));
  if (!auth) return errorResponse(401, "unauthorized", "Invalid or revoked gateway agent key");
  if (!subscriptionAllowsTraffic(auth.plan, auth.subscription_status)) {
    return errorResponse(402, "subscription_inactive", "The subscription for this gateway is inactive");
  }

  const body = await readJsonObject(request);
  const method = requiredString(body, "method", 200);
  const name = optionalScopeName(body);
  const ttlSeconds = parseCapabilityTtl(body.ttlSeconds);
  const policy = parsePolicy(auth.allowed_methods, auth.allowed_names);
  if (!evaluatePolicy(policy, method, name)) {
    return errorResponse(403, "scope_denied", "Requested capability is outside this agent key policy");
  }

  const limiter = auth.plan === "free" ? env.FREE_RATE_LIMITER : env.PAID_RATE_LIMITER;
  const limited = await limiter.limit({ key: `${auth.account_id}:${auth.key_id}:${gatewayId}:capability-issue` });
  if (!limited.success) return errorResponse(429, "rate_limited", "Capability issuance rate limit exceeded");

  const bindArguments = Object.prototype.hasOwnProperty.call(body, "arguments");
  const issued = await issueCapabilityToken(env.CAPABILITY_SIGNING_KEY, {
    accountId: auth.account_id,
    gatewayId,
    apiKeyId: auth.key_id,
    method,
    name,
    ttlSeconds,
    arguments: body.arguments,
    bindArguments,
  });

  return json(
    {
      access_token: issued.token,
      token_type: "Bearer",
      expires_in: issued.expiresIn,
      single_use: true,
      arguments_bound: Boolean(issued.claims.argumentsSha256),
      scope: { gatewayId, method, name },
      jti: issued.claims.jti,
      warning: "Give this short-lived capability to the executor, not the long-lived gateway key.",
    },
    201,
  );
}

async function proxyMcp(
  request: Request,
  env: Env,
  ctx: ExecutionContextLike,
  gatewayId: string,
  span?: TraceSpan,
): Promise<Response> {
  const startedAt = performance.now();
  const requestId = crypto.randomUUID();
  const requestBytes = safeContentLength(request.headers);
  const operation = await extractMcpOperation(request);
  applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name });

  const gateway = await getGateway(env.DB, gatewayId);
  if (!gateway || gateway.enabled !== 1) {
    applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "gateway_not_found", statusCode: 404 });
    return errorResponse(404, "gateway_not_found", "Gateway not found or disabled", requestId);
  }

  const baseTrace = {
    accountId: gateway.account_id,
    gatewayId,
    apiKeyId: null as string | null,
    requestId,
    mcpMethod: operation.method,
    mcpName: operation.name,
    requestBytes,
  };

  if (!operation.consistent) {
    traceResult(env, ctx, startedAt, baseTrace, "operation_mismatch", 400, null);
    applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "operation_mismatch", statusCode: 400 });
    return errorResponse(400, "operation_mismatch", "MCP headers disagree with the JSON-RPC request body", requestId);
  }

  const token = bearerToken(request);
  if (!token) {
    traceResult(env, ctx, startedAt, baseTrace, "unauthorized", 401, null);
    applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "unauthorized", statusCode: 401 });
    return errorResponse(401, "unauthorized", "A gateway agent key or capability is required", requestId);
  }

  let auth: ApiKeyAuthRow | null = null;
  let capability: CapabilityClaims | null = null;
  let authMode: "agent_key" | "capability" = "agent_key";

  if (isCapabilityToken(token)) {
    authMode = "capability";
    try {
      capability = await verifyCapabilityToken(env.CAPABILITY_SIGNING_KEY, token);
    } catch (error) {
      traceResult(env, ctx, startedAt, baseTrace, "capability_invalid", 401, null);
      applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "capability_invalid", statusCode: 401, authMode });
      return errorResponse(401, "invalid_capability", error instanceof Error ? error.message : "Invalid capability", requestId);
    }

    if (capability.gatewayId !== gatewayId || capability.method !== operation.method || capability.name !== operation.name) {
      traceResult(env, ctx, startedAt, baseTrace, "capability_scope_denied", 403, null);
      applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "capability_scope_denied", statusCode: 403, authMode });
      return errorResponse(403, "capability_scope_denied", "Request does not match the capability scope", requestId);
    }
    if (capability.argumentsSha256) {
      if (!operation.hasArguments || !(await capabilityArgumentsMatch(capability, operation.arguments))) {
        traceResult(env, ctx, startedAt, baseTrace, "capability_arguments_denied", 403, null);
        applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "capability_arguments_denied", statusCode: 403, authMode });
        return errorResponse(403, "capability_arguments_denied", "Request arguments do not match the capability", requestId);
      }
    }

    auth = await getApiKeyByIdForGateway(env.DB, gatewayId, capability.apiKeyId);
    if (!auth || auth.account_id !== capability.accountId || capability.accountId !== gateway.account_id) {
      traceResult(env, ctx, startedAt, baseTrace, "capability_parent_invalid", 401, null);
      applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "capability_parent_invalid", statusCode: 401, authMode });
      return errorResponse(401, "invalid_capability", "The capability's parent agent key is invalid or revoked", requestId);
    }
  } else {
    auth = await getApiKeyForGateway(env.DB, gatewayId, await sha256Hex(token));
    if (!auth) {
      traceResult(env, ctx, startedAt, baseTrace, "unauthorized", 401, null);
      applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "unauthorized", statusCode: 401, authMode });
      return errorResponse(401, "unauthorized", "Invalid or revoked gateway agent key", requestId);
    }
  }

  baseTrace.apiKeyId = auth.key_id;

  if (!subscriptionAllowsTraffic(auth.plan, auth.subscription_status)) {
    traceResult(env, ctx, startedAt, baseTrace, "subscription_blocked", 402, null);
    applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "subscription_blocked", statusCode: 402, authMode });
    return errorResponse(402, "subscription_inactive", "The subscription for this gateway is inactive", requestId);
  }

  const policy = parsePolicy(auth.allowed_methods, auth.allowed_names);
  if (!evaluatePolicy(policy, operation.method, operation.name)) {
    traceResult(env, ctx, startedAt, baseTrace, "policy_denied", 403, null);
    applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "policy_denied", statusCode: 403, authMode });
    return errorResponse(403, "policy_denied", "This credential is not allowed to perform the requested MCP operation", requestId);
  }

  const limiter = auth.plan === "free" ? env.FREE_RATE_LIMITER : env.PAID_RATE_LIMITER;
  const limited = await limiter.limit({ key: `${auth.account_id}:${auth.key_id}:${gatewayId}` });
  if (!limited.success) {
    traceResult(env, ctx, startedAt, baseTrace, "rate_limited", 429, null);
    applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "rate_limited", statusCode: 429, authMode });
    return errorResponse(429, "rate_limited", "Gateway request rate limit exceeded", requestId);
  }

  if (capability) {
    let consumed: boolean;
    try {
      consumed = await consumeCapability(env.DB, capability);
    } catch {
      traceResult(env, ctx, startedAt, baseTrace, "replay_store_unavailable", 503, null);
      applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "replay_store_unavailable", statusCode: 503, authMode });
      return errorResponse(503, "replay_store_unavailable", "Capability replay protection is unavailable", requestId);
    }
    if (!consumed) {
      traceResult(env, ctx, startedAt, baseTrace, "capability_replayed", 401, null);
      applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "capability_replayed", statusCode: 401, authMode });
      return errorResponse(401, "capability_replayed", "Capability has already been used", requestId);
    }
  }

  const metered = await consumeMonthlyRequest(env.DB, auth.account_id, auth.plan);
  if (!metered.allowed) {
    traceResult(env, ctx, startedAt, baseTrace, "quota_exceeded", 429, null);
    applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "quota_exceeded", statusCode: 429, authMode });
    return errorResponse(
      429,
      "monthly_quota_exceeded",
      `${auth.plan} plan monthly request quota of ${metered.usage.limit} has been reached`,
      requestId,
    );
  }

  let injectedHeaders: Record<string, string> = {};
  if (gateway.upstream_headers_ciphertext && gateway.upstream_headers_iv) {
    const plaintext = await decryptString(
      gateway.upstream_headers_ciphertext,
      gateway.upstream_headers_iv,
      env.UPSTREAM_ENCRYPTION_KEY,
    );
    injectedHeaders = validateUpstreamHeaders(JSON.parse(plaintext) as unknown);
  }

  const headers = buildUpstreamHeaders(request, injectedHeaders);
  headers.set("X-ContextGateway-Request-Id", requestId);

  try {
    const upstream = await fetch(gateway.upstream_url, {
      method: request.method,
      headers,
      body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
      redirect: "manual",
    });
    const responseHeaders = new Headers(upstream.headers);
    responseHeaders.delete("set-cookie");
    responseHeaders.delete("proxy-authenticate");
    responseHeaders.set("X-ContextGateway-Request-Id", requestId);
    responseHeaders.set("X-ContextGateway-Auth-Mode", authMode);
    responseHeaders.set("Cache-Control", "no-store");

    const responseBytes = safeContentLength(upstream.headers);
    const decision = upstream.ok ? "allowed" : "upstream_error";
    traceResult(env, ctx, startedAt, baseTrace, decision, upstream.status, responseBytes);
    applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision, statusCode: upstream.status, authMode });

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    });
  } catch {
    traceResult(env, ctx, startedAt, baseTrace, "upstream_unreachable", 502, null);
    applySpanAttributes(span, { gatewayId, method: operation.method, name: operation.name, decision: "upstream_unreachable", statusCode: 502, authMode });
    return errorResponse(502, "upstream_unreachable", "The configured MCP server could not be reached", requestId);
  }
}

async function route(request: Request, env: Env, ctx: ExecutionContextLike): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === "GET" && url.pathname === "/healthz") {
    return json({ status: "ok", service: "contextgateway-edge" });
  }

  if (url.pathname.startsWith("/v1/control/")) {
    return handleControlPlane(request, env, url.pathname);
  }

  const capabilityMatch = /^\/v1\/mcp\/([^/]+)\/capabilities$/.exec(url.pathname);
  if (capabilityMatch) {
    const gatewayId = decodeURIComponent(capabilityMatch[1]);
    return issueCapability(request, env, gatewayId);
  }

  const gatewayMatch = /^\/v1\/mcp\/([^/]+)$/.exec(url.pathname);
  if (gatewayMatch) {
    const gatewayId = decodeURIComponent(gatewayMatch[1]);
    if (ctx.tracing) {
      return ctx.tracing.enterSpan("contextgateway.mcp.proxy", (span) => proxyMcp(request, env, ctx, gatewayId, span));
    }
    return proxyMcp(request, env, ctx, gatewayId);
  }

  return errorResponse(404, "not_found", "Route not found");
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContextLike): Promise<Response> {
    try {
      return await route(request, env, ctx);
    } catch {
      return errorResponse(500, "internal_error", "ContextGateway could not process the request");
    }
  },
};
