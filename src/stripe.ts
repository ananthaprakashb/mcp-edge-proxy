import type { Env, Plan, SubscriptionStatus } from "./types";

export type PaidPlan = "pro" | "team";

export interface StripeEvent<T = Record<string, unknown>> {
  id: string;
  type: string;
  data: { object: T };
}

export interface StripeCheckoutSession {
  id: string;
  url: string | null;
  customer: string | null;
  subscription: string | null;
  client_reference_id: string | null;
  metadata?: Record<string, string> | null;
}

export interface StripePortalSession {
  id: string;
  url: string;
}

export interface StripeSubscription {
  id: string;
  status: string;
  customer: string | { id: string };
  metadata?: Record<string, string> | null;
  cancel_at_period_end?: boolean;
  current_period_end?: number;
  items?: { data?: Array<{ price?: { id?: string } }> };
}

function configured(value: string | undefined): value is string {
  return Boolean(value && value.trim());
}

export function stripeCheckoutConfigured(env: Env): boolean {
  return configured(env.STRIPE_SECRET_KEY) && configured(env.STRIPE_PRO_PRICE_ID) && configured(env.STRIPE_TEAM_PRICE_ID);
}

export function stripeWebhookConfigured(env: Env): boolean {
  return configured(env.STRIPE_WEBHOOK_SECRET);
}

export function priceIdForPlan(env: Env, plan: PaidPlan): string {
  const value = plan === "pro" ? env.STRIPE_PRO_PRICE_ID : env.STRIPE_TEAM_PRICE_ID;
  if (!configured(value)) throw new Error(`Stripe ${plan} price is not configured`);
  return value;
}

export function planForPriceId(env: Env, priceId: string): PaidPlan | null {
  if (configured(env.STRIPE_PRO_PRICE_ID) && priceId === env.STRIPE_PRO_PRICE_ID) return "pro";
  if (configured(env.STRIPE_TEAM_PRICE_ID) && priceId === env.STRIPE_TEAM_PRICE_ID) return "team";
  return null;
}

async function stripePost<T>(env: Env, path: string, params: URLSearchParams): Promise<T> {
  if (!configured(env.STRIPE_SECRET_KEY)) throw new Error("Stripe secret key is not configured");
  const response = await fetch(`https://api.stripe.com/v1/${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params.toString(),
  });
  const body = (await response.json()) as Record<string, unknown>;
  if (!response.ok) {
    const stripeError = body.error as { message?: string } | undefined;
    throw new Error(stripeError?.message || `Stripe request failed with HTTP ${response.status}`);
  }
  return body as T;
}

export async function createStripeCustomer(
  env: Env,
  input: { accountId: string; workspaceName: string; email: string },
): Promise<{ id: string }> {
  const params = new URLSearchParams();
  params.set("email", input.email);
  params.set("name", input.workspaceName);
  params.set("metadata[account_id]", input.accountId);
  return stripePost<{ id: string }>(env, "customers", params);
}

export async function createCheckoutSession(
  env: Env,
  input: { accountId: string; customerId: string; plan: PaidPlan; origin: string },
): Promise<StripeCheckoutSession> {
  const params = new URLSearchParams();
  params.set("mode", "subscription");
  params.set("customer", input.customerId);
  params.set("client_reference_id", input.accountId);
  params.set("line_items[0][price]", priceIdForPlan(env, input.plan));
  params.set("line_items[0][quantity]", "1");
  params.set("success_url", `${input.origin}/?billing=success`);
  params.set("cancel_url", `${input.origin}/?billing=cancel`);
  params.set("allow_promotion_codes", "true");
  params.set("metadata[account_id]", input.accountId);
  params.set("metadata[target_plan]", input.plan);
  params.set("subscription_data[metadata][account_id]", input.accountId);
  params.set("subscription_data[metadata][target_plan]", input.plan);
  return stripePost<StripeCheckoutSession>(env, "checkout/sessions", params);
}

export async function createPortalSession(
  env: Env,
  input: { customerId: string; origin: string },
): Promise<StripePortalSession> {
  const params = new URLSearchParams();
  params.set("customer", input.customerId);
  params.set("return_url", input.origin);
  return stripePost<StripePortalSession>(env, "billing_portal/sessions", params);
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function timingSafeHexEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let i = 0; i < left.length; i += 1) mismatch |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return mismatch === 0;
}

async function hmacSha256Hex(secret: string, payload: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  return hex(new Uint8Array(signature));
}

export async function verifyStripeSignature(
  rawBody: string,
  signatureHeader: string | null,
  secret: string | undefined,
  nowMs = Date.now(),
): Promise<boolean> {
  if (!signatureHeader || !configured(secret)) return false;
  let timestamp: number | null = null;
  const signatures: string[] = [];
  for (const part of signatureHeader.split(",")) {
    const [key, value] = part.split("=", 2);
    if (key === "t") timestamp = Number(value);
    if (key === "v1" && value) signatures.push(value);
  }
  if (!timestamp || !Number.isFinite(timestamp) || signatures.length === 0) return false;
  const ageSeconds = Math.abs(Math.floor(nowMs / 1000) - timestamp);
  if (ageSeconds > 300) return false;
  const expected = await hmacSha256Hex(secret, `${timestamp}.${rawBody}`);
  return signatures.some((candidate) => timingSafeHexEqual(expected, candidate));
}

export function stripeCustomerId(value: StripeSubscription["customer"]): string {
  return typeof value === "string" ? value : value.id;
}

export function stripeSubscriptionPriceId(subscription: StripeSubscription): string | null {
  return subscription.items?.data?.[0]?.price?.id ?? null;
}

export function subscriptionStatus(status: string): SubscriptionStatus {
  if (status === "active") return "active";
  if (status === "trialing") return "trialing";
  if (status === "canceled") return "canceled";
  return "past_due";
}

export function stripePeriodEnd(value: number | undefined): string | null {
  if (!value || !Number.isFinite(value)) return null;
  return new Date(value * 1000).toISOString();
}

export function parsePaidPlan(value: unknown): PaidPlan {
  if (value === "pro" || value === "team") return value;
  throw new Error("plan must be pro or team");
}

export function isPlan(value: unknown): value is Plan {
  return value === "free" || value === "pro" || value === "team";
}
