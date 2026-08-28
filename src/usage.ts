import { getPlanEntitlements } from "./entitlements";
import type { D1Database, Plan } from "./types";

export interface MonthlyUsage {
  month: string;
  used: number;
  limit: number;
  remaining: number;
}

export function usageMonth(date = new Date()): string {
  return date.toISOString().slice(0, 7);
}

export async function getMonthlyUsage(db: D1Database, accountId: string, plan: Plan): Promise<MonthlyUsage> {
  const month = usageMonth();
  const row = await db
    .prepare(`SELECT request_count FROM usage_monthly WHERE account_id = ? AND usage_month = ?`)
    .bind(accountId, month)
    .first<{ request_count: number }>();
  const used = Number(row?.request_count ?? 0);
  const limit = getPlanEntitlements(plan).monthlyRequestLimit;
  return { month, used, limit, remaining: Math.max(0, limit - used) };
}

export async function consumeMonthlyRequest(
  db: D1Database,
  accountId: string,
  plan: Plan,
): Promise<{ allowed: boolean; usage: MonthlyUsage }> {
  const month = usageMonth();
  const limit = getPlanEntitlements(plan).monthlyRequestLimit;

  const row = await db
    .prepare(
      `INSERT INTO usage_monthly (account_id, usage_month, request_count, updated_at)
       VALUES (?, ?, 1, datetime('now'))
       ON CONFLICT(account_id, usage_month) DO UPDATE SET
         request_count = usage_monthly.request_count + 1,
         updated_at = datetime('now')
       WHERE usage_monthly.request_count < ?
       RETURNING request_count`,
    )
    .bind(accountId, month, limit)
    .first<{ request_count: number }>();

  if (row) {
    const used = Number(row.request_count);
    return {
      allowed: true,
      usage: { month, used, limit, remaining: Math.max(0, limit - used) },
    };
  }

  return { allowed: false, usage: await getMonthlyUsage(db, accountId, plan) };
}
