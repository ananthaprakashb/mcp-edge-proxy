import type { D1Database, Plan, SubscriptionStatus } from "./types";

export interface BillingAccount {
  id: string;
  name: string;
  plan: Plan;
  subscription_status: SubscriptionStatus;
  billing_customer_id: string | null;
  billing_subscription_id: string | null;
  billing_price_id: string | null;
  billing_period_end: string | null;
  billing_cancel_at_period_end: number;
}

export async function getBillingAccount(db: D1Database, accountId: string): Promise<BillingAccount | null> {
  return db
    .prepare(
      `SELECT id, name, plan, subscription_status, billing_customer_id,
              billing_subscription_id, billing_price_id, billing_period_end,
              billing_cancel_at_period_end
       FROM accounts WHERE id = ?`,
    )
    .bind(accountId)
    .first<BillingAccount>();
}

export async function setBillingCustomer(db: D1Database, accountId: string, customerId: string): Promise<void> {
  await db
    .prepare(`UPDATE accounts SET billing_customer_id = ? WHERE id = ?`)
    .bind(customerId, accountId)
    .run();
}

export async function attachCheckoutSubscription(
  db: D1Database,
  accountId: string,
  customerId: string,
  subscriptionId: string | null,
): Promise<void> {
  await db
    .prepare(
      `UPDATE accounts
       SET billing_customer_id = ?, billing_subscription_id = COALESCE(?, billing_subscription_id)
       WHERE id = ?`,
    )
    .bind(customerId, subscriptionId, accountId)
    .run();
}

export async function updatePaidSubscription(
  db: D1Database,
  input: {
    accountId: string;
    customerId: string;
    subscriptionId: string;
    priceId: string;
    plan: "pro" | "team";
    status: SubscriptionStatus;
    periodEnd: string | null;
    cancelAtPeriodEnd: boolean;
  },
): Promise<void> {
  await db
    .prepare(
      `UPDATE accounts
       SET plan = ?, subscription_status = ?, billing_customer_id = ?, billing_subscription_id = ?,
           billing_price_id = ?, billing_period_end = ?, billing_cancel_at_period_end = ?
       WHERE id = ?`,
    )
    .bind(
      input.plan,
      input.status,
      input.customerId,
      input.subscriptionId,
      input.priceId,
      input.periodEnd,
      input.cancelAtPeriodEnd ? 1 : 0,
      input.accountId,
    )
    .run();
}

export async function downgradeToFree(db: D1Database, accountId: string, customerId?: string | null): Promise<void> {
  await db
    .prepare(
      `UPDATE accounts
       SET plan = 'free', subscription_status = 'free',
           billing_customer_id = COALESCE(?, billing_customer_id),
           billing_subscription_id = NULL, billing_price_id = NULL,
           billing_period_end = NULL, billing_cancel_at_period_end = 0
       WHERE id = ?`,
    )
    .bind(customerId ?? null, accountId)
    .run();
}

export async function findAccountIdForStripe(
  db: D1Database,
  customerId: string | null,
  metadataAccountId: string | null,
): Promise<string | null> {
  if (metadataAccountId) {
    const account = await db.prepare(`SELECT id FROM accounts WHERE id = ?`).bind(metadataAccountId).first<{ id: string }>();
    if (account) return account.id;
  }
  if (!customerId) return null;
  const account = await db
    .prepare(`SELECT id FROM accounts WHERE billing_customer_id = ?`)
    .bind(customerId)
    .first<{ id: string }>();
  return account?.id ?? null;
}

export async function claimStripeEvent(db: D1Database, eventId: string, eventType: string): Promise<boolean> {
  const row = await db
    .prepare(
      `INSERT INTO stripe_events (event_id, event_type, status)
       VALUES (?, ?, 'processing')
       ON CONFLICT(event_id) DO NOTHING
       RETURNING event_id`,
    )
    .bind(eventId, eventType)
    .first<{ event_id: string }>();
  return Boolean(row);
}

export async function completeStripeEvent(db: D1Database, eventId: string): Promise<void> {
  await db
    .prepare(`UPDATE stripe_events SET status = 'processed', processed_at = datetime('now') WHERE event_id = ?`)
    .bind(eventId)
    .run();
}

export async function releaseStripeEvent(db: D1Database, eventId: string): Promise<void> {
  await db
    .prepare(`DELETE FROM stripe_events WHERE event_id = ? AND status = 'processing'`)
    .bind(eventId)
    .run();
}

export async function getResourceCounts(
  db: D1Database,
  accountId: string,
): Promise<{ gateways: number; activeKeys: number; members: number }> {
  const gateway = await db
    .prepare(`SELECT COUNT(*) AS count FROM gateways WHERE account_id = ? AND enabled = 1`)
    .bind(accountId)
    .first<{ count: number }>();
  const keys = await db
    .prepare(`SELECT COUNT(*) AS count FROM api_keys WHERE account_id = ? AND revoked_at IS NULL`)
    .bind(accountId)
    .first<{ count: number }>();
  const members = await db
    .prepare(
      `SELECT COUNT(*) AS count
       FROM workspace_members m JOIN workspaces w ON w.id = m.workspace_id
       WHERE w.account_id = ?`,
    )
    .bind(accountId)
    .first<{ count: number }>();
  return {
    gateways: Number(gateway?.count ?? 0),
    activeKeys: Number(keys?.count ?? 0),
    members: Number(members?.count ?? 0),
  };
}
