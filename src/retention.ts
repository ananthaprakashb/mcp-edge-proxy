import { appendSecurityEvent, pruneAuditEventsBefore, verifyAuditChain } from "./audit-db";
import { getPlanEntitlements } from "./entitlements";
import type { D1Database, Plan } from "./types";

interface AccountRetentionRow {
  id: string;
  plan: Plan;
  workspace_id: string | null;
}

export interface RetentionRunResult {
  runId: string;
  accountId: string;
  plan: Plan;
  traceRetentionDays: number;
  auditRetentionDays: number;
  tracesDeleted: number;
  auditEventsDeleted: number;
  integrityValid: boolean;
  integrityReason?: string;
  status: "completed" | "failed";
  errorMessage?: string;
}

export function retentionCutoff(nowMs: number, days: number): string {
  return new Date(nowMs - days * 86_400_000).toISOString();
}

async function countBefore(db: D1Database, table: "traces" | "security_events", accountId: string, cutoff: string): Promise<number> {
  const row = await db
    .prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE account_id = ? AND datetime(created_at) < datetime(?)`)
    .bind(accountId, cutoff)
    .first<{ count: number }>();
  return Number(row?.count ?? 0);
}

async function deleteTracesBefore(db: D1Database, accountId: string, cutoff: string): Promise<number> {
  const count = await countBefore(db, "traces", accountId, cutoff);
  if (!count) return 0;
  await db
    .prepare(`DELETE FROM traces WHERE account_id = ? AND datetime(created_at) < datetime(?)`)
    .bind(accountId, cutoff)
    .run();
  return count;
}

async function updateRun(
  db: D1Database,
  runId: string,
  input: {
    status: "completed" | "failed";
    tracesDeleted: number;
    auditEventsDeleted: number;
    integrityFailures: number;
    errorMessage?: string | null;
  },
): Promise<void> {
  await db
    .prepare(
      `UPDATE retention_runs
       SET status = ?, accounts_processed = 1, traces_deleted = ?, audit_events_deleted = ?,
           integrity_failures = ?, error_message = ?, completed_at = ?
       WHERE id = ?`,
    )
    .bind(
      input.status,
      input.tracesDeleted,
      input.auditEventsDeleted,
      input.integrityFailures,
      input.errorMessage ?? null,
      new Date().toISOString(),
      runId,
    )
    .run();
}

export async function runRetentionForAccount(
  db: D1Database,
  account: AccountRetentionRow,
  options: {
    triggerType: "scheduled" | "manual";
    requestedByUserId?: string | null;
    scheduledTime?: number;
    nowMs?: number;
  },
): Promise<RetentionRunResult> {
  const nowMs = options.nowMs ?? options.scheduledTime ?? Date.now();
  const entitlement = getPlanEntitlements(account.plan);
  const runId = crypto.randomUUID();
  const startedAt = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO retention_runs
       (id, trigger_type, requested_by_user_id, account_id, status, scheduled_time, started_at)
       VALUES (?, ?, ?, ?, 'running', ?, ?)`,
    )
    .bind(
      runId,
      options.triggerType,
      options.requestedByUserId ?? null,
      account.id,
      options.scheduledTime ? new Date(options.scheduledTime).toISOString() : null,
      startedAt,
    )
    .run();

  let tracesDeleted = 0;
  let auditEventsDeleted = 0;
  try {
    tracesDeleted = await deleteTracesBefore(
      db,
      account.id,
      retentionCutoff(nowMs, entitlement.traceRetentionDays),
    );

    const verification = await verifyAuditChain(db, account.id);
    if (!verification.valid) {
      const message = `Audit integrity verification failed: ${verification.reason ?? "unknown"}`;
      await updateRun(db, runId, {
        status: "failed",
        tracesDeleted,
        auditEventsDeleted: 0,
        integrityFailures: 1,
        errorMessage: message,
      });
      return {
        runId,
        accountId: account.id,
        plan: account.plan,
        traceRetentionDays: entitlement.traceRetentionDays,
        auditRetentionDays: entitlement.auditRetentionDays,
        tracesDeleted,
        auditEventsDeleted: 0,
        integrityValid: false,
        integrityReason: verification.reason,
        status: "failed",
        errorMessage: message,
      };
    }

    auditEventsDeleted = await pruneAuditEventsBefore(
      db,
      account.id,
      retentionCutoff(nowMs, entitlement.auditRetentionDays),
    );

    await appendSecurityEvent(db, {
      accountId: account.id,
      workspaceId: account.workspace_id,
      actorUserId: options.requestedByUserId ?? null,
      eventType: "retention_cleanup_completed",
      targetType: "account",
      targetId: account.id,
      metadata: {
        triggerType: options.triggerType,
        traceRetentionDays: entitlement.traceRetentionDays,
        auditRetentionDays: entitlement.auditRetentionDays,
        tracesDeleted,
        auditEventsDeleted,
        integrityVerified: true,
        runId,
      },
    });

    await updateRun(db, runId, {
      status: "completed",
      tracesDeleted,
      auditEventsDeleted,
      integrityFailures: 0,
    });
    return {
      runId,
      accountId: account.id,
      plan: account.plan,
      traceRetentionDays: entitlement.traceRetentionDays,
      auditRetentionDays: entitlement.auditRetentionDays,
      tracesDeleted,
      auditEventsDeleted,
      integrityValid: true,
      status: "completed",
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Retention cleanup failed";
    await updateRun(db, runId, {
      status: "failed",
      tracesDeleted,
      auditEventsDeleted,
      integrityFailures: 0,
      errorMessage: message,
    }).catch(() => undefined);
    return {
      runId,
      accountId: account.id,
      plan: account.plan,
      traceRetentionDays: entitlement.traceRetentionDays,
      auditRetentionDays: entitlement.auditRetentionDays,
      tracesDeleted,
      auditEventsDeleted,
      integrityValid: false,
      status: "failed",
      errorMessage: message,
    };
  }
}

export async function runRetentionLifecycle(
  db: D1Database,
  options: {
    triggerType: "scheduled" | "manual";
    accountId?: string | null;
    requestedByUserId?: string | null;
    scheduledTime?: number;
    nowMs?: number;
  },
): Promise<RetentionRunResult[]> {
  const conditions = options.accountId ? "WHERE a.id = ?" : "";
  const statement = db.prepare(
    `SELECT a.id, a.plan, w.id AS workspace_id
     FROM accounts a
     LEFT JOIN workspaces w ON w.account_id = a.id
     ${conditions}
     ORDER BY datetime(a.created_at) ASC`,
  );
  const result = options.accountId
    ? await statement.bind(options.accountId).all<AccountRetentionRow>()
    : await statement.all<AccountRetentionRow>();
  const accounts = result.results ?? [];
  const runs: RetentionRunResult[] = [];
  for (const account of accounts) {
    runs.push(await runRetentionForAccount(db, account, options));
  }
  return runs;
}

export async function getRetentionSummary(db: D1Database, accountId: string, plan: Plan) {
  const entitlement = getPlanEntitlements(plan);
  const [traceStats, auditStats, lastRun, verification] = await Promise.all([
    db
      .prepare(`SELECT COUNT(*) AS count, MIN(datetime(created_at)) AS oldest FROM traces WHERE account_id = ?`)
      .bind(accountId)
      .first<{ count: number; oldest: string | null }>(),
    db
      .prepare(`SELECT COUNT(*) AS count, MIN(datetime(created_at)) AS oldest FROM security_events WHERE account_id = ?`)
      .bind(accountId)
      .first<{ count: number; oldest: string | null }>(),
    db
      .prepare(
        `SELECT id, trigger_type, status, traces_deleted, audit_events_deleted, integrity_failures,
                error_message, started_at, completed_at
         FROM retention_runs
         WHERE account_id = ?
         ORDER BY datetime(started_at) DESC
         LIMIT 1`,
      )
      .bind(accountId)
      .first<Record<string, unknown>>(),
    verifyAuditChain(db, accountId),
  ]);
  return {
    policy: {
      traceRetentionDays: entitlement.traceRetentionDays,
      auditRetentionDays: entitlement.auditRetentionDays,
    },
    storage: {
      traces: Number(traceStats?.count ?? 0),
      oldestTraceAt: traceStats?.oldest ?? null,
      auditEvents: Number(auditStats?.count ?? 0),
      oldestAuditEventAt: auditStats?.oldest ?? null,
    },
    integrity: verification,
    lastRun,
  };
}
