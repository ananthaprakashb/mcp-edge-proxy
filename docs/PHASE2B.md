# Phase 2B — billing, entitlements, and exact usage

Phase 2B adds Free/Pro/Team entitlements, exact monthly D1 request accounting, Stripe Checkout, the Stripe Customer Portal, and signed webhook-driven subscription state.

## Plans

| Plan | Price | Active gateways | Active agent keys | Members | Authorized requests / month |
| --- | ---: | ---: | ---: | ---: | ---: |
| Free | $0 | 1 | 2 | 1 | 10,000 |
| Pro | $19/mo | 10 | 25 | 3 | 100,000 |
| Team | $49/mo | 50 | 100 | 15 | 1,000,000 |

The monthly counter is separate from Cloudflare's per-minute rate-limit bindings. Rate limiting is for abuse protection; D1 is the exact product-usage source of truth.

Only requests that pass agent-key authentication, subscription checks, MCP policy, and the per-minute limiter consume monthly quota. Policy-denied, unauthorized, subscription-blocked, and edge-rate-limited requests do not consume monthly quota.

## 1. Apply the D1 migration

After the Phase 2B PR is merged:

```bash
npm install
npm run db:migrate:remote
```

Migration `0003_billing_usage.sql` creates `usage_monthly` and `stripe_events` and extends the existing account billing metadata.

## 2. Create Stripe products and recurring prices

Start in Stripe **test mode**.

Create two monthly recurring prices:

- ContextGateway Pro — $19 USD / month
- ContextGateway Team — $49 USD / month

Copy the two resulting `price_...` identifiers.

## 3. Configure Worker billing values

Never commit Stripe values to the repository. Set them directly in Cloudflare:

```bash
npx wrangler secret put STRIPE_SECRET_KEY
npx wrangler secret put STRIPE_PRO_PRICE_ID
npx wrangler secret put STRIPE_TEAM_PRICE_ID
```

Price IDs are not confidential, but storing all deployment-specific Stripe values through Worker secrets keeps the public repository environment-neutral.

Do not reuse `CONTROL_PLANE_TOKEN`, `BETTER_AUTH_SECRET`, or any upstream credential as a Stripe secret.

## 4. Deploy once

```bash
npm run typecheck
npm test
npm run build
npm run deploy
```

Open **Billing & usage**. The dashboard will show that Checkout is configured but keep upgrade buttons disabled until the signed webhook path is also configured.

## 5. Create the Stripe webhook endpoint

In Stripe Workbench / Webhooks, add the production endpoint:

```text
https://YOUR-CONTEXTGATEWAY-HOST/v1/billing/stripe/webhook
```

Subscribe to:

- `checkout.session.completed`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`

Reveal the endpoint signing secret (`whsec_...`) and store it directly in Cloudflare:

```bash
npx wrangler secret put STRIPE_WEBHOOK_SECRET
```

Deploy again so the Worker receives the new secret:

```bash
npm run deploy
```

ContextGateway verifies the raw request body against the `Stripe-Signature` header with a five-minute timestamp tolerance. The body is parsed only after signature verification.

## 6. Test Checkout in Stripe test mode

As the workspace owner:

1. open **Billing & usage**;
2. choose Pro or Team;
3. complete Stripe Checkout with a Stripe test card;
4. return to ContextGateway;
5. refresh Billing & usage;
6. verify the plan/status changed from the webhook, not merely from the redirect;
7. open **Manage billing** and verify the Stripe Customer Portal works.

A successful Checkout redirect is not treated as proof of payment. Subscription state is updated only by verified Stripe webhook events.

## 7. Validate product limits

Free validation:

- second active gateway -> `409 plan_limit_reached`
- third active agent key -> `409 plan_limit_reached`

Monthly request validation can be inspected directly without generating 10,000 calls:

```bash
npx wrangler d1 execute mcp-context --remote --command "SELECT * FROM usage_monthly ORDER BY usage_month DESC;"
```

Do not manually alter production usage counters except in a disposable test workspace.

## 8. Cancellation behavior

If Stripe marks a subscription `cancel_at_period_end`, ContextGateway keeps paid access while the subscription remains active and displays the scheduled end date.

When Stripe sends `customer.subscription.deleted` (or a canceled subscription state), ContextGateway returns the account to the Free plan and clears the paid subscription metadata. Existing resources are retained, but new resource creation is constrained by Free limits; future product work can add a guided over-limit cleanup flow.

## Security properties

- Stripe secret keys and webhook signing secrets never enter D1.
- Webhooks are verified before JSON parsing or subscription mutation.
- Webhook event IDs are idempotently recorded.
- A handler failure releases its event claim so Stripe retries can be processed.
- Checkout and Customer Portal creation require the workspace owner session.
- Browser redirects never directly activate a paid plan.
- Usage metering does not store prompts, MCP arguments, or response bodies.
