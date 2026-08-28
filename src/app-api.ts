import { createAuth, authProviderAvailability } from "./auth";
import {
  createWorkspace,
  getWorkspaceMembership,
  getWorkspaceOverview,
  listGatewayKeys,
  listWorkspaceGateways,
  listWorkspaceTraces,
  listWorkspacesForUser,
  workspaceSlugExists,
  type WorkspaceMembership,
} from "./app-db";
import { getBillingAccount, getResourceCounts, setBillingCustomer } from "./billing-db";
import { encryptString, generateAgentKey, sha256Hex } from "./crypto";
import { allPlanEntitlements, getPlanEntitlements } from "./entitlements";
import { parseExecutionMode } from "./execution-mode";
import { createApiKey, createGateway, getGateway, revokeApiKey, updateApiKeyExecutionMode } from "./db";
import { normalizePolicyInput } from "./policy";
import { validateUpstreamHeaders, validateUpstreamUrl } from "./security";
import {
  createCheckoutSession,
  createPortalSession,
  createStripeCustomer,
  parsePaidPlan,
  stripeCheckoutConfigured,
  stripeWebhookConfigured,
} from "./stripe";
import { getMonthlyUsage } from "./usage";
import type { Env } from "./types";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function errorResponse(status: number, code: string, message: string): Response {
  return json({ error: { code, message } }, status);
}

async function readJsonObject(request: Request): Promise<Record<string, unknown>> {
  const body = (await request.json()) as unknown;
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("JSON request body must be an object");
  return body as Record<string, unknown>;
}

function requiredString(body: Record<string, unknown>, field: string, maxLength = 300): string {
  const value = body[field];
  if (typeof value !== "string" || value.trim().length === 0 || value.length > maxLength) {
    throw new Error(`${field} must be a non-empty string no longer than ${maxLength} characters`);
  }
  return value.trim();
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 48) || "workspace";
}

async function uniqueSlug(env: Env, name: string): Promise<string> {
  const base = slugify(name);
  if (!(await workspaceSlugExists(env.DB, base))) return base;
  for (let i = 0; i < 6; i += 1) {
    const candidate = `${base}-${crypto.randomUUID().slice(0, 6)}`;
    if (!(await workspaceSlugExists(env.DB, candidate))) return candidate;
  }
  throw new Error("Could not allocate a workspace slug");
}

function canWrite(membership: WorkspaceMembership): boolean {
  return membership.role === "owner" || membership.role === "admin";
}

function canManageBilling(membership: WorkspaceMembership): boolean {
  return membership.role === "owner";
}

async function sessionUser(request: Request, env: Env): Promise<{ id: string; email: string; name: string; image?: string | null } | null> {
  const auth = createAuth(env, request);
  const session = await auth.api.getSession({ headers: request.headers });
  if (!session?.user) return null;
  return {
    id: session.user.id,
    email: session.user.email,
    name: session.user.name,
    image: session.user.image,
  };
}

async function requireMembership(
  env: Env,
  userId: string,
  workspaceId: string,
  write = false,
): Promise<WorkspaceMembership | Response> {
  const membership = await getWorkspaceMembership(env.DB, workspaceId, userId);
  if (!membership) return errorResponse(404, "workspace_not_found", "Workspace not found");
  if (write && !canWrite(membership)) return errorResponse(403, "forbidden", "Owner or admin role is required");
  return membership;
}

async function requireBillingOwner(env: Env, userId: string, workspaceId: string): Promise<WorkspaceMembership | Response> {
  const membership = await requireMembership(env, userId, workspaceId);
  if (membership instanceof Response) return membership;
  if (!canManageBilling(membership)) return errorResponse(403, "forbidden", "Workspace owner role is required for billing changes");
  return membership;
}

export async function handleAppApi(request: Request, env: Env, path: string): Promise<Response> {
  try {
    if (request.method === "GET" && path === "/v1/app/config") {
      return json({
        service: "ContextGateway",
        auth: {
          emailPassword: true,
          ...authProviderAvailability(env),
        },
        billing: {
          checkoutConfigured: stripeCheckoutConfigured(env),
          webhookConfigured: stripeWebhookConfigured(env),
          plans: allPlanEntitlements(),
        },
      });
    }

    const user = await sessionUser(request, env);
    if (!user) return errorResponse(401, "unauthorized", "Sign in is required");

    if (request.method === "GET" && path === "/v1/app/bootstrap") {
      return json({ user, workspaces: await listWorkspacesForUser(env.DB, user.id) });
    }

    if (request.method === "POST" && path === "/v1/app/workspaces") {
      const body = await readJsonObject(request);
      const name = requiredString(body, "name", 120);
      const workspace = {
        id: crypto.randomUUID(),
        accountId: crypto.randomUUID(),
        userId: user.id,
        name,
        slug: await uniqueSlug(env, name),
      };
      await createWorkspace(env.DB, workspace);
      const membership = await getWorkspaceMembership(env.DB, workspace.id, user.id);
      return json({ workspace: membership }, 201);
    }

    const overviewMatch = /^\/v1\/app\/workspaces\/([^/]+)\/overview$/.exec(path);
    if (request.method === "GET" && overviewMatch) {
      const workspaceId = decodeURIComponent(overviewMatch[1]);
      const membership = await requireMembership(env, user.id, workspaceId);
      if (membership instanceof Response) return membership;
      return json({ workspace: membership, metrics: await getWorkspaceOverview(env.DB, membership.account_id) });
    }

    const billingMatch = /^\/v1\/app\/workspaces\/([^/]+)\/billing$/.exec(path);
    if (request.method === "GET" && billingMatch) {
      const workspaceId = decodeURIComponent(billingMatch[1]);
      const membership = await requireMembership(env, user.id, workspaceId);
      if (membership instanceof Response) return membership;
      const account = await getBillingAccount(env.DB, membership.account_id);
      if (!account) return errorResponse(404, "account_not_found", "Billing account not found");
      return json({
        workspace: membership,
        billing: account,
        entitlements: getPlanEntitlements(account.plan),
        usage: await getMonthlyUsage(env.DB, account.id, account.plan),
        resources: await getResourceCounts(env.DB, account.id),
        stripe: {
          checkoutConfigured: stripeCheckoutConfigured(env),
          webhookConfigured: stripeWebhookConfigured(env),
          hasCustomer: Boolean(account.billing_customer_id),
        },
      });
    }

    const checkoutMatch = /^\/v1\/app\/workspaces\/([^/]+)\/billing\/checkout$/.exec(path);
    if (request.method === "POST" && checkoutMatch) {
      const workspaceId = decodeURIComponent(checkoutMatch[1]);
      const membership = await requireBillingOwner(env, user.id, workspaceId);
      if (membership instanceof Response) return membership;
      if (!stripeCheckoutConfigured(env)) return errorResponse(503, "billing_not_configured", "Stripe Checkout is not configured yet");
      const body = await readJsonObject(request);
      const targetPlan = parsePaidPlan(body.plan);
      const account = await getBillingAccount(env.DB, membership.account_id);
      if (!account) return errorResponse(404, "account_not_found", "Billing account not found");
      if (account.billing_subscription_id && (account.subscription_status === "active" || account.subscription_status === "trialing")) {
        return errorResponse(409, "subscription_exists", "Use Manage billing to change an existing paid subscription");
      }

      let customerId = account.billing_customer_id;
      if (!customerId) {
        const customer = await createStripeCustomer(env, {
          accountId: account.id,
          workspaceName: membership.name,
          email: user.email,
        });
        customerId = customer.id;
        await setBillingCustomer(env.DB, account.id, customerId);
      }

      const session = await createCheckoutSession(env, {
        accountId: account.id,
        customerId,
        plan: targetPlan,
        origin: new URL(request.url).origin,
      });
      if (!session.url) throw new Error("Stripe Checkout did not return a redirect URL");
      return json({ url: session.url });
    }

    const portalMatch = /^\/v1\/app\/workspaces\/([^/]+)\/billing\/portal$/.exec(path);
    if (request.method === "POST" && portalMatch) {
      const workspaceId = decodeURIComponent(portalMatch[1]);
      const membership = await requireBillingOwner(env, user.id, workspaceId);
      if (membership instanceof Response) return membership;
      if (!stripeCheckoutConfigured(env)) return errorResponse(503, "billing_not_configured", "Stripe billing is not configured yet");
      const account = await getBillingAccount(env.DB, membership.account_id);
      if (!account?.billing_customer_id) return errorResponse(409, "billing_customer_missing", "Start a paid subscription before opening the billing portal");
      const session = await createPortalSession(env, {
        customerId: account.billing_customer_id,
        origin: new URL(request.url).origin,
      });
      return json({ url: session.url });
    }

    const gatewaysMatch = /^\/v1\/app\/workspaces\/([^/]+)\/gateways$/.exec(path);
    if (gatewaysMatch) {
      const workspaceId = decodeURIComponent(gatewaysMatch[1]);
      const membership = await requireMembership(env, user.id, workspaceId, request.method === "POST");
      if (membership instanceof Response) return membership;

      if (request.method === "GET") {
        return json({ gateways: await listWorkspaceGateways(env.DB, membership.account_id) });
      }

      if (request.method === "POST") {
        const counts = await getResourceCounts(env.DB, membership.account_id);
        const entitlement = getPlanEntitlements(membership.plan);
        if (counts.gateways >= entitlement.gatewayLimit) {
          return errorResponse(409, "plan_limit_reached", `${entitlement.displayName} allows ${entitlement.gatewayLimit} active gateway${entitlement.gatewayLimit === 1 ? "" : "s"}`);
        }
        const body = await readJsonObject(request);
        const upstreamUrl = requiredString(body, "upstreamUrl", 2048);
        const parsedUrl = validateUpstreamUrl(upstreamUrl, env.ALLOW_INSECURE_UPSTREAMS === "true");
        const upstreamHeaders = validateUpstreamHeaders(body.upstreamHeaders);
        let ciphertext: string | null = null;
        let iv: string | null = null;
        if (Object.keys(upstreamHeaders).length > 0) {
          const encrypted = await encryptString(JSON.stringify(upstreamHeaders), env.UPSTREAM_ENCRYPTION_KEY);
          ciphertext = encrypted.ciphertext;
          iv = encrypted.iv;
        }
        const gateway = {
          id: crypto.randomUUID(),
          accountId: membership.account_id,
          name: requiredString(body, "name", 120),
          upstreamUrl: parsedUrl.toString(),
          upstreamHeadersCiphertext: ciphertext,
          upstreamHeadersIv: iv,
        };
        await createGateway(env.DB, gateway);
        return json(
          {
            gateway: {
              id: gateway.id,
              name: gateway.name,
              upstreamUrl: gateway.upstreamUrl,
              mcpEndpoint: `/v1/mcp/${gateway.id}`,
            },
          },
          201,
        );
      }
    }

    const keysMatch = /^\/v1\/app\/workspaces\/([^/]+)\/gateways\/([^/]+)\/keys$/.exec(path);
    if (keysMatch) {
      const workspaceId = decodeURIComponent(keysMatch[1]);
      const gatewayId = decodeURIComponent(keysMatch[2]);
      const membership = await requireMembership(env, user.id, workspaceId, request.method === "POST");
      if (membership instanceof Response) return membership;
      const gateway = await getGateway(env.DB, gatewayId);
      if (!gateway || gateway.account_id !== membership.account_id) return errorResponse(404, "gateway_not_found", "Gateway not found");

      if (request.method === "GET") {
        return json({ keys: await listGatewayKeys(env.DB, membership.account_id, gatewayId) });
      }

      if (request.method === "POST") {
        const counts = await getResourceCounts(env.DB, membership.account_id);
        const entitlement = getPlanEntitlements(membership.plan);
        if (counts.activeKeys >= entitlement.activeKeyLimit) {
          return errorResponse(409, "plan_limit_reached", `${entitlement.displayName} allows ${entitlement.activeKeyLimit} active agent keys`);
        }
        const body = await readJsonObject(request);
        const allowedMethods = normalizePolicyInput(body.allowedMethods);
        const allowedNames = normalizePolicyInput(body.allowedNames);
        const executionMode = parseExecutionMode(body.executionMode);
        const secret = generateAgentKey();
        const key = {
          id: crypto.randomUUID(),
          accountId: membership.account_id,
          gatewayId,
          name: requiredString(body, "name", 120),
          secretHash: await sha256Hex(secret),
          keyPrefix: secret.slice(0, 18),
          allowedMethods,
          allowedNames,
          executionMode,
        };
        await createApiKey(env.DB, key);
        return json(
          {
            key: {
              id: key.id,
              name: key.name,
              key: secret,
              keyPrefix: key.keyPrefix,
              allowedMethods,
              allowedNames,
              executionMode,
            },
            warning: executionMode === "capability_required"
              ? "This plaintext key is shown only once and may be used only to mint short-lived capabilities."
              : "This plaintext key is shown only once.",
          },
          201,
        );
      }
    }

    const keyMatch = /^\/v1\/app\/workspaces\/([^/]+)\/gateways\/([^/]+)\/keys\/([^/]+)$/.exec(path);
    if ((request.method === "PATCH" || request.method === "DELETE") && keyMatch) {
      const workspaceId = decodeURIComponent(keyMatch[1]);
      const gatewayId = decodeURIComponent(keyMatch[2]);
      const keyId = decodeURIComponent(keyMatch[3]);
      const membership = await requireMembership(env, user.id, workspaceId, true);
      if (membership instanceof Response) return membership;
      const gateway = await getGateway(env.DB, gatewayId);
      if (!gateway || gateway.account_id !== membership.account_id) return errorResponse(404, "gateway_not_found", "Gateway not found");
      const key = await env.DB
        .prepare(`SELECT id, revoked_at FROM api_keys WHERE id = ? AND gateway_id = ? AND account_id = ?`)
        .bind(keyId, gatewayId, membership.account_id)
        .first<{ id: string; revoked_at: string | null }>();
      if (!key) return errorResponse(404, "key_not_found", "Agent key not found");

      if (request.method === "DELETE") {
        await revokeApiKey(env.DB, keyId);
        return new Response(null, { status: 204 });
      }
      if (key.revoked_at) return errorResponse(409, "key_revoked", "A revoked key cannot change execution mode");
      const body = await readJsonObject(request);
      const executionMode = parseExecutionMode(body.executionMode);
      await updateApiKeyExecutionMode(env.DB, keyId, executionMode);
      return json({ keyId, executionMode });
    }

    const tracesMatch = /^\/v1\/app\/workspaces\/([^/]+)\/traces$/.exec(path);
    if (request.method === "GET" && tracesMatch) {
      const workspaceId = decodeURIComponent(tracesMatch[1]);
      const membership = await requireMembership(env, user.id, workspaceId);
      if (membership instanceof Response) return membership;
      const url = new URL(request.url);
      const requestedLimit = Number(url.searchParams.get("limit") ?? "100");
      const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(250, Math.floor(requestedLimit))) : 100;
      return json({
        traces: await listWorkspaceTraces(env.DB, membership.account_id, {
          gatewayId: url.searchParams.get("gatewayId"),
          decision: url.searchParams.get("decision"),
          authMode: url.searchParams.get("authMode"),
          q: url.searchParams.get("q"),
          limit,
        }),
      });
    }

    return errorResponse(404, "not_found", "Application route not found");
  } catch (error) {
    return errorResponse(400, "invalid_request", error instanceof Error ? error.message : "Invalid request");
  }
}
