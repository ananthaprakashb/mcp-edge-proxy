import {
  capabilityArgumentsMatch,
  consumeCapability,
  isCapabilityToken,
  verifyCapabilityToken,
  type CapabilityClaims,
} from "./capability";
import {
  getLatestContextDocument,
  listLatestContextDocuments,
  matchingContextPolicies,
  recordContextDocumentAccess,
} from "./context-db";
import { normalizeDocumentKey, pathAllowed, readJsonPointer } from "./context-document";
import { getApiKeyByIdForGateway, insertSecurityEvent, insertTrace } from "./db";
import { capabilitySigningKeyring } from "./keyring";
import { evaluatePolicyDetailed, parsePolicy } from "./policy";
import { consumeMonthlyRequest } from "./usage";
import type { Env, ExecutionContextLike } from "./types";

const LIST_TOOL = "contextgateway.document.list";
const READ_TOOL = "contextgateway.document.read";

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function errorResponse(status: number, code: string, message: string): Response {
  return json({ error: { code, message } }, status);
}

function bearerToken(request: Request): string | null {
  const value = request.headers.get("authorization");
  return value ? /^Bearer\s+(.+)$/i.exec(value)?.[1] ?? null : null;
}

function activeSubscription(plan: string, status: string): boolean {
  return plan === "free" || status === "active" || status === "trialing";
}

function parseStringArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

async function verifyWithKeyring(env: Env, token: string): Promise<CapabilityClaims> {
  let lastError: unknown;
  for (const signingKey of Object.values(capabilitySigningKeyring(env).keys)) {
    try {
      return await verifyCapabilityToken(signingKey, token);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error("Invalid capability token");
}

function toolResult(id: unknown, payload: unknown, meta: Record<string, unknown>): Response {
  const text = JSON.stringify(payload);
  return json({
    jsonrpc: "2.0",
    id: id ?? null,
    result: {
      content: [{ type: "text", text }],
      structuredContent: payload,
      _meta: meta,
    },
  });
}

async function traceContextDecision(
  env: Env,
  ctx: ExecutionContextLike,
  input: {
    gatewayId: string;
    accountId: string;
    apiKeyId: string;
    requestId: string;
    toolName: string;
    decision: string;
    statusCode: number;
    startedAt: number;
    capabilityJti?: string | null;
    reason: string;
  },
): Promise<void> {
  ctx.waitUntil(insertTrace(env.DB, {
    id: crypto.randomUUID(),
    accountId: input.accountId,
    gatewayId: input.gatewayId,
    apiKeyId: input.apiKeyId,
    requestId: input.requestId,
    mcpMethod: "tools/call",
    mcpName: input.toolName,
    decision: input.decision,
    statusCode: input.statusCode,
    durationMs: Math.max(0, Math.round(performance.now() - input.startedAt)),
    requestBytes: null,
    responseBytes: null,
    authMode: "capability",
    capabilityJti: input.capabilityJti ?? null,
    policyReason: input.reason,
    policyMethodRule: "tools/call",
    policyNameRule: input.toolName,
  }).catch(() => undefined));
}

function documentIsActive(row: { effective_at: string | null; expires_at: string | null }, now = Date.now()): { active: boolean; reason?: string } {
  if (row.effective_at && Date.parse(row.effective_at) > now) return { active: false, reason: "document_not_effective" };
  if (row.expires_at && Date.parse(row.expires_at) <= now) return { active: false, reason: "document_expired" };
  return { active: true };
}

async function accessAllowed(
  env: Env,
  input: { accountId: string; documentKey: string; gatewayId: string; apiKeyId: string; operation: "read" | "list"; path?: string | null },
): Promise<{ allowed: boolean; reason: string; allowedPaths: string[] }> {
  const policies = await matchingContextPolicies(env.DB, input.accountId, input.documentKey, input.gatewayId, input.apiKeyId);
  if (!policies.length) return { allowed: false, reason: "document_policy_missing", allowedPaths: [] };

  const paths = new Set<string>();
  let operationMatched = false;
  for (const policy of policies) {
    const operations = parseStringArray(policy.allowed_operations_json);
    if (!operations.includes(input.operation)) continue;
    operationMatched = true;
    for (const path of parseStringArray(policy.allowed_paths_json)) paths.add(path);
  }
  if (!operationMatched) return { allowed: false, reason: "document_operation_not_allowed", allowedPaths: [] };
  const allowedPaths = [...paths];
  if (input.operation === "read" && !pathAllowed(allowedPaths, input.path ?? null)) {
    return { allowed: false, reason: "document_path_not_allowed", allowedPaths };
  }
  return { allowed: true, reason: "document_policy_allowed", allowedPaths };
}

async function recordDenied(
  env: Env,
  ctx: ExecutionContextLike,
  input: {
    accountId: string;
    workspaceId?: string | null;
    documentId?: string | null;
    documentKey: string;
    documentVersion: number;
    contentHash: string;
    gatewayId: string;
    apiKeyId: string;
    requestedPath?: string | null;
    reason: string;
    capabilityJti: string;
  },
): Promise<void> {
  ctx.waitUntil(Promise.all([
    recordContextDocumentAccess(env.DB, {
      accountId: input.accountId,
      workspaceId: input.workspaceId,
      documentId: input.documentId,
      documentKey: input.documentKey,
      documentVersion: input.documentVersion,
      contentHash: input.contentHash,
      gatewayId: input.gatewayId,
      apiKeyId: input.apiKeyId,
      operation: "read",
      requestedPath: input.requestedPath,
      decision: "denied",
      reason: input.reason,
      capabilityJti: input.capabilityJti,
    }),
    insertSecurityEvent(env.DB, {
      accountId: input.accountId,
      workspaceId: input.workspaceId,
      eventType: "context_document_access_denied",
      targetType: "context_document",
      targetId: input.documentId ?? input.documentKey,
      metadata: {
        documentKey: input.documentKey,
        documentVersion: input.documentVersion,
        contentHash: input.contentHash,
        gatewayId: input.gatewayId,
        apiKeyId: input.apiKeyId,
        requestedPath: input.requestedPath ?? null,
        reason: input.reason,
      },
    }),
  ]).then(() => undefined).catch(() => undefined));
}

export async function handleGovernedContextMcp(
  request: Request,
  env: Env,
  ctx: ExecutionContextLike,
  gatewayId: string,
): Promise<Response | null> {
  if (request.method !== "POST") return null;
  let body: Record<string, unknown>;
  try {
    const parsed = await request.clone().json() as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    body = parsed as Record<string, unknown>;
  } catch {
    return null;
  }
  if (body.method !== "tools/call" || !body.params || typeof body.params !== "object" || Array.isArray(body.params)) return null;
  const params = body.params as Record<string, unknown>;
  const toolName = typeof params.name === "string" ? params.name : "";
  if (toolName !== LIST_TOOL && toolName !== READ_TOOL) return null;
  const startedAt = performance.now();
  const requestId = request.headers.get("x-request-id") || crypto.randomUUID();

  const token = bearerToken(request);
  if (!token || !isCapabilityToken(token)) {
    return errorResponse(403, "context_capability_required", "Governed context tools require a short-lived ContextGateway capability");
  }

  let claims: CapabilityClaims;
  try {
    claims = await verifyWithKeyring(env, token);
  } catch {
    return errorResponse(401, "capability_invalid", "Capability signature, expiry, or claims are invalid");
  }
  if (claims.gatewayId !== gatewayId || claims.method !== "tools/call" || claims.name !== toolName) {
    return errorResponse(403, "capability_scope_denied", "Capability does not match this governed context operation");
  }
  const auth = await getApiKeyByIdForGateway(env.DB, gatewayId, claims.apiKeyId);
  if (!auth || auth.account_id !== claims.accountId) {
    return errorResponse(401, "capability_parent_invalid", "Capability parent key is revoked or mismatched");
  }
  if (!activeSubscription(auth.plan, auth.subscription_status)) {
    return errorResponse(402, "subscription_inactive", "The subscription for this gateway is inactive");
  }
  const keyPolicy = evaluatePolicyDetailed(parsePolicy(auth.allowed_methods, auth.allowed_names), "tools/call", toolName);
  if (!keyPolicy.allowed) return errorResponse(403, "policy_denied", `Current agent key policy no longer allows this context tool: ${keyPolicy.reason}`);

  const args = params.arguments && typeof params.arguments === "object" && !Array.isArray(params.arguments)
    ? params.arguments as Record<string, unknown>
    : {};
  if (toolName === READ_TOOL && !claims.argumentsSha256) {
    return errorResponse(403, "context_arguments_binding_required", "Document read capabilities must be bound to exact arguments");
  }
  if (!(await capabilityArgumentsMatch(claims, args))) {
    return errorResponse(403, "capability_arguments_denied", "Capability arguments do not match this governed context request");
  }

  if (toolName === LIST_TOOL) {
    const documents = await listLatestContextDocuments(env.DB, auth.account_id);
    const visible: Array<Record<string, unknown>> = [];
    for (const document of documents) {
      if (!documentIsActive(document).active) continue;
      const policy = await accessAllowed(env, {
        accountId: auth.account_id,
        documentKey: document.document_key,
        gatewayId,
        apiKeyId: auth.key_id,
        operation: "list",
      });
      if (!policy.allowed) continue;
      visible.push({
        documentKey: document.document_key,
        title: document.title,
        format: document.format,
        version: document.version,
        contentHash: document.content_hash,
        schemaName: document.schema_name,
        schemaVersion: document.schema_version,
        effectiveAt: document.effective_at,
        expiresAt: document.expires_at,
      });
    }

    const limiter = auth.plan === "free" ? env.FREE_RATE_LIMITER : env.PAID_RATE_LIMITER;
    if (!(await limiter.limit({ key: `${auth.account_id}:${auth.key_id}:${gatewayId}:context` })).success) {
      return errorResponse(429, "rate_limited", "Governed context rate limit exceeded");
    }
    const usage = await consumeMonthlyRequest(env.DB, auth.account_id, auth.plan);
    if (!usage.allowed) return errorResponse(429, "quota_exceeded", "Monthly request quota exceeded");
    if (!(await consumeCapability(env.DB, claims))) return errorResponse(401, "capability_replayed", "Capability was already consumed");

    ctx.waitUntil(Promise.all(visible.map((document) => recordContextDocumentAccess(env.DB, {
      accountId: auth.account_id,
      documentKey: String(document.documentKey),
      documentVersion: Number(document.version),
      contentHash: String(document.contentHash),
      gatewayId,
      apiKeyId: auth.key_id,
      operation: "list",
      decision: "allowed",
      reason: "document_policy_allowed",
      capabilityJti: claims.jti,
    }))).then(() => undefined).catch(() => undefined));
    void traceContextDecision(env, ctx, {
      gatewayId,
      accountId: auth.account_id,
      apiKeyId: auth.key_id,
      requestId,
      toolName,
      decision: "context_allowed",
      statusCode: 200,
      startedAt,
      capabilityJti: claims.jti,
      reason: "context_document_list_allowed",
    });
    return toolResult(body.id, { documents: visible }, { capabilityJti: claims.jti, count: visible.length });
  }

  let documentKey: string;
  try {
    documentKey = normalizeDocumentKey(args.documentKey);
  } catch (error) {
    return errorResponse(400, "invalid_document_key", error instanceof Error ? error.message : "Invalid documentKey");
  }
  const requestedPath = args.path === undefined || args.path === null || args.path === ""
    ? null
    : typeof args.path === "string" ? args.path : "__invalid__";
  if (requestedPath === "__invalid__" || (requestedPath && !requestedPath.startsWith("/"))) {
    return errorResponse(400, "invalid_document_path", "path must be a JSON-pointer-style path beginning with /");
  }

  const document = await getLatestContextDocument(env.DB, auth.account_id, documentKey);
  if (!document) return errorResponse(404, "document_not_found", "Document not found");
  const active = documentIsActive(document);
  if (!active.active) {
    await recordDenied(env, ctx, {
      accountId: auth.account_id,
      workspaceId: document.workspace_id,
      documentId: document.id,
      documentKey,
      documentVersion: document.version,
      contentHash: document.content_hash,
      gatewayId,
      apiKeyId: auth.key_id,
      requestedPath,
      reason: active.reason ?? "document_inactive",
      capabilityJti: claims.jti,
    });
    return errorResponse(403, active.reason ?? "document_inactive", "Document is not currently effective");
  }

  const access = await accessAllowed(env, {
    accountId: auth.account_id,
    documentKey,
    gatewayId,
    apiKeyId: auth.key_id,
    operation: "read",
    path: requestedPath,
  });
  if (!access.allowed) {
    await recordDenied(env, ctx, {
      accountId: auth.account_id,
      workspaceId: document.workspace_id,
      documentId: document.id,
      documentKey,
      documentVersion: document.version,
      contentHash: document.content_hash,
      gatewayId,
      apiKeyId: auth.key_id,
      requestedPath,
      reason: access.reason,
      capabilityJti: claims.jti,
    });
    return errorResponse(403, "document_access_denied", `Governed context policy denied this read: ${access.reason}`);
  }

  let normalized: unknown;
  try {
    normalized = document.normalized_json ? JSON.parse(document.normalized_json) as unknown : null;
  } catch {
    return errorResponse(500, "document_normalization_invalid", "Stored normalized document content is invalid");
  }
  let selected: unknown;
  try {
    selected = readJsonPointer(normalized, requestedPath);
  } catch {
    return errorResponse(404, "document_path_not_found", "Requested document path does not exist");
  }

  const limiter = auth.plan === "free" ? env.FREE_RATE_LIMITER : env.PAID_RATE_LIMITER;
  if (!(await limiter.limit({ key: `${auth.account_id}:${auth.key_id}:${gatewayId}:context` })).success) {
    return errorResponse(429, "rate_limited", "Governed context rate limit exceeded");
  }
  const usage = await consumeMonthlyRequest(env.DB, auth.account_id, auth.plan);
  if (!usage.allowed) return errorResponse(429, "quota_exceeded", "Monthly request quota exceeded");
  if (!(await consumeCapability(env.DB, claims))) return errorResponse(401, "capability_replayed", "Capability was already consumed");

  ctx.waitUntil(recordContextDocumentAccess(env.DB, {
    accountId: auth.account_id,
    workspaceId: document.workspace_id,
    documentId: document.id,
    documentKey,
    documentVersion: document.version,
    contentHash: document.content_hash,
    gatewayId,
    apiKeyId: auth.key_id,
    operation: "read",
    requestedPath,
    decision: "allowed",
    reason: "document_policy_allowed",
    capabilityJti: claims.jti,
  }).catch(() => undefined));
  void traceContextDecision(env, ctx, {
    gatewayId,
    accountId: auth.account_id,
    apiKeyId: auth.key_id,
    requestId,
    toolName,
    decision: "context_allowed",
    statusCode: 200,
    startedAt,
    capabilityJti: claims.jti,
    reason: "context_document_read_allowed",
  });

  return toolResult(body.id, {
    documentKey,
    title: document.title,
    version: document.version,
    contentHash: document.content_hash,
    path: requestedPath,
    value: selected,
    provenance: {
      sourceLabel: document.source_label,
      schemaName: document.schema_name,
      schemaVersion: document.schema_version,
      effectiveAt: document.effective_at,
      expiresAt: document.expires_at,
      createdAt: document.created_at,
    },
  }, {
    capabilityJti: claims.jti,
    documentId: document.id,
    policyReason: access.reason,
  });
}
