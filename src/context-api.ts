import { getWorkspaceMembership } from "./app-db";
import { createAuth } from "./auth";
import {
  createContextDocument,
  findDuplicateContextDocument,
  grantContextDocumentPolicy,
  listContextDocumentPolicies,
  listContextDocumentVersions,
  listLatestContextDocuments,
  revokeContextDocumentPolicy,
} from "./context-db";
import {
  normalizeAllowedOperations,
  normalizeAllowedPaths,
  normalizeDocumentKey,
  parseContextDocument,
  parseContextDocumentFormat,
} from "./context-document";
import { insertSecurityEvent } from "./db";
import type { Env } from "./types";

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function errorResponse(status: number, code: string, message: string, extra?: Record<string, unknown>): Response {
  return json({ error: { code, message, ...(extra ?? {}) } }, status);
}

async function readObject(request: Request): Promise<Record<string, unknown>> {
  const body = await request.json() as unknown;
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("JSON request body must be an object");
  return body as Record<string, unknown>;
}

function requiredString(body: Record<string, unknown>, field: string, max: number): string {
  const value = body[field];
  if (typeof value !== "string" || !value.trim() || value.length > max) {
    throw new Error(`${field} must be a non-empty string no longer than ${max} characters`);
  }
  return value.trim();
}

function optionalString(body: Record<string, unknown>, field: string, max: number): string | null {
  const value = body[field];
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || value.length > max) throw new Error(`${field} must be a string no longer than ${max} characters`);
  return value.trim();
}

function optionalDate(body: Record<string, unknown>, field: string): string | null {
  const value = optionalString(body, field, 64);
  if (!value) return null;
  const time = Date.parse(value);
  if (!Number.isFinite(time)) throw new Error(`${field} must be an ISO-compatible date/time`);
  return new Date(time).toISOString();
}

function documentSummary(row: Record<string, unknown>) {
  return {
    id: row.id,
    documentKey: row.document_key,
    title: row.title,
    format: row.format,
    schemaName: row.schema_name,
    schemaVersion: row.schema_version,
    sourceLabel: row.source_label,
    version: Number(row.version),
    contentHash: row.content_hash,
    byteSize: Number(row.byte_size),
    effectiveAt: row.effective_at,
    expiresAt: row.expires_at,
    supersededAt: row.superseded_at,
    createdAt: row.created_at,
  };
}

async function userForRequest(request: Request, env: Env) {
  return (await createAuth(env, request).api.getSession({ headers: request.headers }))?.user ?? null;
}

export async function handleContextApi(request: Request, env: Env, path: string): Promise<Response | null> {
  const listMatch = /^\/v1\/app\/workspaces\/([^/]+)\/documents$/.exec(path);
  const validateMatch = /^\/v1\/app\/workspaces\/([^/]+)\/documents\/validate$/.exec(path);
  const documentMatch = /^\/v1\/app\/workspaces\/([^/]+)\/documents\/([^/]+)$/.exec(path);
  const policiesMatch = /^\/v1\/app\/workspaces\/([^/]+)\/documents\/([^/]+)\/policies$/.exec(path);
  const policyMatch = /^\/v1\/app\/workspaces\/([^/]+)\/documents\/([^/]+)\/policies\/([^/]+)$/.exec(path);
  const match = validateMatch || policiesMatch || policyMatch || documentMatch || listMatch;
  if (!match) return null;

  try {
    const user = await userForRequest(request, env);
    if (!user) return errorResponse(401, "unauthorized", "Sign in is required");
    const workspaceId = decodeURIComponent(match[1]);
    const membership = await getWorkspaceMembership(env.DB, workspaceId, user.id);
    if (!membership) return errorResponse(404, "workspace_not_found", "Workspace not found");
    const manager = membership.role === "owner" || membership.role === "admin";

    if (validateMatch && request.method === "POST") {
      if (!manager) return errorResponse(403, "forbidden", "Owner or admin role is required to validate ingestion content");
      const body = await readObject(request);
      const format = parseContextDocumentFormat(body.format);
      const content = requiredString(body, "content", 400_000);
      const parsed = await parseContextDocument(format, content);
      return json({
        valid: true,
        format,
        contentHash: parsed.contentHash,
        byteSize: parsed.byteSize,
        topLevelKeys: parsed.topLevelKeys,
      });
    }

    if (listMatch && request.method === "GET") {
      const [documents, policies] = await Promise.all([
        listLatestContextDocuments(env.DB, membership.account_id),
        listContextDocumentPolicies(env.DB, membership.account_id),
      ]);
      const policyCounts = new Map<string, number>();
      for (const policy of policies) policyCounts.set(policy.document_key, (policyCounts.get(policy.document_key) ?? 0) + 1);
      return json({
        documents: documents.map((row) => ({ ...documentSummary(row as unknown as Record<string, unknown>), policyCount: policyCounts.get(row.document_key) ?? 0 })),
      });
    }

    if (listMatch && request.method === "POST") {
      if (!manager) return errorResponse(403, "forbidden", "Owner or admin role is required to ingest documents");
      const body = await readObject(request);
      const documentKey = normalizeDocumentKey(body.documentKey);
      const title = requiredString(body, "title", 160);
      const format = parseContextDocumentFormat(body.format);
      const content = requiredString(body, "content", 400_000);
      const parsed = await parseContextDocument(format, content);
      const duplicate = await findDuplicateContextDocument(env.DB, membership.account_id, parsed.contentHash);
      if (duplicate) {
        return errorResponse(409, "duplicate_document", "This exact document content is already stored in the workspace", {
          existingDocumentId: duplicate.id,
          existingDocumentKey: duplicate.document_key,
          existingVersion: duplicate.version,
          contentHash: duplicate.content_hash,
        });
      }

      const effectiveAt = optionalDate(body, "effectiveAt");
      const expiresAt = optionalDate(body, "expiresAt");
      if (effectiveAt && expiresAt && Date.parse(expiresAt) <= Date.parse(effectiveAt)) {
        throw new Error("expiresAt must be later than effectiveAt");
      }

      const row = await createContextDocument(env.DB, {
        accountId: membership.account_id,
        workspaceId,
        documentKey,
        title,
        format,
        schemaName: optionalString(body, "schemaName", 120),
        schemaVersion: optionalString(body, "schemaVersion", 80),
        sourceLabel: optionalString(body, "sourceLabel", 240),
        contentHash: parsed.contentHash,
        byteSize: parsed.byteSize,
        rawContent: content,
        normalizedJson: parsed.normalizedJson,
        effectiveAt,
        expiresAt,
        createdByUserId: user.id,
      });

      let policyId: string | null = null;
      if (body.policy && typeof body.policy === "object" && !Array.isArray(body.policy)) {
        const policy = body.policy as Record<string, unknown>;
        policyId = await grantContextDocumentPolicy(env.DB, {
          accountId: membership.account_id,
          workspaceId,
          documentKey,
          gatewayId: optionalString(policy, "gatewayId", 100),
          apiKeyId: optionalString(policy, "apiKeyId", 100),
          allowedPaths: normalizeAllowedPaths(policy.allowedPaths),
          allowedOperations: normalizeAllowedOperations(policy.allowedOperations),
          createdByUserId: user.id,
        });
      }

      await insertSecurityEvent(env.DB, {
        accountId: membership.account_id,
        workspaceId,
        actorUserId: user.id,
        eventType: "context_document_ingested",
        targetType: "context_document",
        targetId: row.id,
        metadata: {
          documentKey,
          version: row.version,
          format,
          contentHash: parsed.contentHash,
          byteSize: parsed.byteSize,
          schemaName: row.schema_name,
          schemaVersion: row.schema_version,
          policyCreated: Boolean(policyId),
        },
      });
      return json({ document: documentSummary(row as unknown as Record<string, unknown>), policyId }, 201);
    }

    if (documentMatch && request.method === "GET") {
      const documentKey = normalizeDocumentKey(decodeURIComponent(documentMatch[2]));
      const [versions, policies] = await Promise.all([
        listContextDocumentVersions(env.DB, membership.account_id, documentKey),
        listContextDocumentPolicies(env.DB, membership.account_id, documentKey),
      ]);
      if (!versions.length) return errorResponse(404, "document_not_found", "Document not found");
      return json({
        documentKey,
        versions: versions.map((row) => documentSummary(row as unknown as Record<string, unknown>)),
        policies,
      });
    }

    if (policiesMatch && request.method === "GET") {
      const documentKey = normalizeDocumentKey(decodeURIComponent(policiesMatch[2]));
      return json({ policies: await listContextDocumentPolicies(env.DB, membership.account_id, documentKey) });
    }

    if (policiesMatch && request.method === "POST") {
      if (!manager) return errorResponse(403, "forbidden", "Owner or admin role is required to grant document access");
      const documentKey = normalizeDocumentKey(decodeURIComponent(policiesMatch[2]));
      const versions = await listContextDocumentVersions(env.DB, membership.account_id, documentKey);
      if (!versions.length) return errorResponse(404, "document_not_found", "Document not found");
      const body = await readObject(request);
      const policyId = await grantContextDocumentPolicy(env.DB, {
        accountId: membership.account_id,
        workspaceId,
        documentKey,
        gatewayId: optionalString(body, "gatewayId", 100),
        apiKeyId: optionalString(body, "apiKeyId", 100),
        allowedPaths: normalizeAllowedPaths(body.allowedPaths),
        allowedOperations: normalizeAllowedOperations(body.allowedOperations),
        createdByUserId: user.id,
      });
      await insertSecurityEvent(env.DB, {
        accountId: membership.account_id,
        workspaceId,
        actorUserId: user.id,
        eventType: "context_document_policy_granted",
        targetType: "context_document_policy",
        targetId: policyId,
        metadata: { documentKey },
      });
      return json({ policyId }, 201);
    }

    if (policyMatch && request.method === "DELETE") {
      if (!manager) return errorResponse(403, "forbidden", "Owner or admin role is required to revoke document access");
      const documentKey = normalizeDocumentKey(decodeURIComponent(policyMatch[2]));
      const policyId = decodeURIComponent(policyMatch[3]);
      await revokeContextDocumentPolicy(env.DB, membership.account_id, policyId);
      await insertSecurityEvent(env.DB, {
        accountId: membership.account_id,
        workspaceId,
        actorUserId: user.id,
        eventType: "context_document_policy_revoked",
        targetType: "context_document_policy",
        targetId: policyId,
        metadata: { documentKey },
      });
      return new Response(null, { status: 204 });
    }

    return errorResponse(405, "method_not_allowed", "Method not allowed for governed context route");
  } catch (error) {
    return errorResponse(400, "invalid_request", error instanceof Error ? error.message : "Invalid request");
  }
}
