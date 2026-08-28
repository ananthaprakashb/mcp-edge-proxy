import {
  attachCheckoutSubscription,
  claimStripeEvent,
  completeStripeEvent,
  downgradeToFree,
  findAccountIdForStripe,
  releaseStripeEvent,
  updatePaidSubscription,
} from "./billing-db";
import {
  planForPriceId,
  stripeCustomerId,
  stripePeriodEnd,
  stripeSubscriptionPriceId,
  subscriptionStatus,
  verifyStripeSignature,
  type StripeCheckoutSession,
  type StripeEvent,
  type StripeSubscription,
} from "./stripe";
import type { Env } from "./types";

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function metadataAccountId(metadata: Record<string, string> | null | undefined): string | null {
  const value = metadata?.account_id;
  return value && value.length <= 100 ? value : null;
}

async function processCheckout(env: Env, session: StripeCheckoutSession): Promise<void> {
  const customerId = session.customer;
  const accountId = await findAccountIdForStripe(
    env.DB,
    customerId,
    metadataAccountId(session.metadata) ?? session.client_reference_id,
  );
  if (!accountId || !customerId) return;
  await attachCheckoutSubscription(env.DB, accountId, customerId, session.subscription ?? null);
}

async function processSubscription(env: Env, subscription: StripeSubscription, deleted: boolean): Promise<void> {
  const customerId = stripeCustomerId(subscription.customer);
  const accountId = await findAccountIdForStripe(env.DB, customerId, metadataAccountId(subscription.metadata));
  if (!accountId) return;

  if (deleted || subscription.status === "canceled") {
    await downgradeToFree(env.DB, accountId, customerId);
    return;
  }

  const priceId = stripeSubscriptionPriceId(subscription);
  if (!priceId) throw new Error("Stripe subscription does not contain a price");
  const plan = planForPriceId(env, priceId);
  if (!plan) throw new Error(`Stripe subscription price ${priceId} is not mapped to a ContextGateway plan`);

  await updatePaidSubscription(env.DB, {
    accountId,
    customerId,
    subscriptionId: subscription.id,
    priceId,
    plan,
    status: subscriptionStatus(subscription.status),
    periodEnd: stripePeriodEnd(subscription.current_period_end),
    cancelAtPeriodEnd: Boolean(subscription.cancel_at_period_end),
  });
}

export async function handleStripeWebhook(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  const rawBody = await request.text();
  const valid = await verifyStripeSignature(rawBody, request.headers.get("stripe-signature"), env.STRIPE_WEBHOOK_SECRET);
  if (!valid) return json({ error: "invalid_signature" }, 400);

  let event: StripeEvent;
  try {
    event = JSON.parse(rawBody) as StripeEvent;
  } catch {
    return json({ error: "invalid_json" }, 400);
  }
  if (!event.id || !event.type || !event.data?.object) return json({ error: "invalid_event" }, 400);

  const claimed = await claimStripeEvent(env.DB, event.id, event.type);
  if (!claimed) return json({ received: true, duplicate: true });

  try {
    if (event.type === "checkout.session.completed") {
      await processCheckout(env, event.data.object as unknown as StripeCheckoutSession);
    } else if (event.type === "customer.subscription.created" || event.type === "customer.subscription.updated") {
      await processSubscription(env, event.data.object as unknown as StripeSubscription, false);
    } else if (event.type === "customer.subscription.deleted") {
      await processSubscription(env, event.data.object as unknown as StripeSubscription, true);
    }
    await completeStripeEvent(env.DB, event.id);
    return json({ received: true });
  } catch (error) {
    await releaseStripeEvent(env.DB, event.id);
    return json({ error: error instanceof Error ? error.message : "webhook_processing_failed" }, 500);
  }
}
