import { computeAuditEventHash } from "./audit-integrity";
import type { D1Database, D1PreparedStatement } from "./types";

export interface SecurityEventInput {
  accountId: string;
  workspaceId?: string | null;
  actorUserId?: string | null;
  eventType: string;
  targetType: string;
  targetId: string;
  metadata?: Record<string, unknown>;
}

interface AuditRow {
  id: string;
  account_id: string;
  workspace_id: string | null;
  actor_user_id: string | null;
  event_type: string;
  target_type: string;
  target_id: string;
  metadata_json: string;
  created_at: string;
  chain_sequence: number | null;
  previous_hash: string | null;
  event_hash: string | null;
}

interface ChainAnchor {
  pruned_through_sequence: number;
  pruned_through_hash: string | null;
}

interface ChainHead {
  sequence: number;
  hash: string | null;
}

export interface AuditVerificationResult {
  valid: boolean;
  checkedEvents: number;
  anchorSequence: number;
  anchorHash: string | null;
  headSequence: number;
  headHash: string | null;
  brokenEventId?: string;
  reason?: string;
}

async function getAnchor(db: D1Database, accountId: string): Promise<ChainAnchor> {
  return (
    await db
      .prepare(`SELECT pruned_through_sequence, pruned_through_hash FROM audit_chain_anchors WHERE account_id = ?`)
      .bind(accountId)
      .first<ChainAnchor>()
  ) ?? { pruned_through_sequence: 0, pruned_through_hash: null };
}

async function getHead(db: D1Database, accountId: string): Promise<ChainHead> {
  const row = await db
    .prepare(
      `SELECT chain_sequence, event_hash
       FROM security_events
       WHERE account_id = ? AND chain_sequence IS NOT NULL AND event_hash IS NOT NULL
       ORDER BY chain_sequence DESC
       LIMIT 1`,
    )
    .bind(accountId)
    .first<{ chain_sequence: number; event_hash: string }>();
  if (row) return { sequence: Number(row.chain_sequence), hash: row.event_hash };
  const anchor = await getAnchor(db, accountId);
  return { sequence: Number(anchor.pruned_through_sequence), hash: anchor.pruned_through_hash };
}

function hashFields(row: AuditRow, sequence: number, previousHash: string | null) {
  return {
    id: row.id,
    accountId: row.account_id,
    workspaceId: row.workspace_id,
    actorUserId: row.actor_user_id,
    eventType: row.event_type,
    targetType: row.target_type,
    targetId: row.target_id,
    metadataJson: row.metadata_json,
    createdAt: row.created_at,
    chainSequence: sequence,
    previousHash,
  };
}

export async function ensureAuditChainBackfilled(db: D1Database, accountId: string): Promise<void> {
  let head = await getHead(db, accountId);
  while (true) {
    const result = await db
      .prepare(
        `SELECT id, account_id, workspace_id, actor_user_id, event_type, target_type, target_id,
                metadata_json, created_at, chain_sequence, previous_hash, event_hash
         FROM security_events
         WHERE account_id = ? AND event_hash IS NULL
         ORDER BY datetime(created_at) ASC, id ASC
         LIMIT 100`,
      )
      .bind(accountId)
      .all<AuditRow>();
    const rows = result.results ?? [];
    if (!rows.length) return;

    const statements: D1PreparedStatement[] = [];
    let nextHead = head;
    for (const row of rows) {
      const sequence = nextHead.sequence + 1;
      const previousHash = nextHead.hash;
      const eventHash = await computeAuditEventHash(hashFields(row, sequence, previousHash));
      statements.push(
        db
          .prepare(
            `UPDATE security_events
             SET chain_sequence = ?, previous_hash = ?, event_hash = ?
             WHERE id = ? AND event_hash IS NULL`,
          )
          .bind(sequence, previousHash, eventHash, row.id),
      );
      nextHead = { sequence, hash: eventHash };
    }
    try {
      await db.batch(statements);
      head = nextHead;
    } catch {
      // Another request may have sealed the same legacy batch first. Re-read the head and continue.
      head = await getHead(db, accountId);
    }
  }
}

export async function appendSecurityEvent(db: D1Database, event: SecurityEventInput): Promise<void> {
  const metadataJson = JSON.stringify(event.metadata ?? {});
  await ensureAuditChainBackfilled(db, event.accountId);

  let lastError: unknown;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const head = await getHead(db, event.accountId);
    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    const sequence = head.sequence + 1;
    const eventHash = await computeAuditEventHash({
      id,
      accountId: event.accountId,
      workspaceId: event.workspaceId ?? null,
      actorUserId: event.actorUserId ?? null,
      eventType: event.eventType,
      targetType: event.targetType,
      targetId: event.targetId,
      metadataJson,
      createdAt,
      chainSequence: sequence,
      previousHash: head.hash,
    });
    try {
      await db
        .prepare(
          `INSERT INTO security_events
           (id, account_id, workspace_id, actor_user_id, event_type, target_type, target_id,
            metadata_json, created_at, chain_sequence, previous_hash, event_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          id,
          event.accountId,
          event.workspaceId ?? null,
          event.actorUserId ?? null,
          event.eventType,
          event.targetType,
          event.targetId,
          metadataJson,
          createdAt,
          sequence,
          head.hash,
          eventHash,
        )
        .run();
      return;
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error("Could not append security audit event");
}

export async function verifyAuditChain(db: D1Database, accountId: string): Promise<AuditVerificationResult> {
  await ensureAuditChainBackfilled(db, accountId);
  const anchor = await getAnchor(db, accountId);
  const result = await db
    .prepare(
      `SELECT id, account_id, workspace_id, actor_user_id, event_type, target_type, target_id,
              metadata_json, created_at, chain_sequence, previous_hash, event_hash
       FROM security_events
       WHERE account_id = ?
       ORDER BY chain_sequence ASC`,
    )
    .bind(accountId)
    .all<AuditRow>();
  const rows = result.results ?? [];

  let expectedSequence = Number(anchor.pruned_through_sequence) + 1;
  let expectedPreviousHash = anchor.pruned_through_hash;
  for (const row of rows) {
    if (row.chain_sequence !== expectedSequence) {
      return {
        valid: false,
        checkedEvents: expectedSequence - Number(anchor.pruned_through_sequence) - 1,
        anchorSequence: Number(anchor.pruned_through_sequence),
        anchorHash: anchor.pruned_through_hash,
        headSequence: expectedSequence - 1,
        headHash: expectedPreviousHash,
        brokenEventId: row.id,
        reason: "chain_sequence_mismatch",
      };
    }
    if (row.previous_hash !== expectedPreviousHash || !row.event_hash) {
      return {
        valid: false,
        checkedEvents: expectedSequence - Number(anchor.pruned_through_sequence) - 1,
        anchorSequence: Number(anchor.pruned_through_sequence),
        anchorHash: anchor.pruned_through_hash,
        headSequence: expectedSequence - 1,
        headHash: expectedPreviousHash,
        brokenEventId: row.id,
        reason: "previous_hash_mismatch",
      };
    }
    const computed = await computeAuditEventHash(hashFields(row, row.chain_sequence, row.previous_hash));
    if (computed !== row.event_hash) {
      return {
        valid: false,
        checkedEvents: expectedSequence - Number(anchor.pruned_through_sequence) - 1,
        anchorSequence: Number(anchor.pruned_through_sequence),
        anchorHash: anchor.pruned_through_hash,
        headSequence: expectedSequence - 1,
        headHash: expectedPreviousHash,
        brokenEventId: row.id,
        reason: "event_hash_mismatch",
      };
    }
    expectedSequence += 1;
    expectedPreviousHash = row.event_hash;
  }

  return {
    valid: true,
    checkedEvents: rows.length,
    anchorSequence: Number(anchor.pruned_through_sequence),
    anchorHash: anchor.pruned_through_hash,
    headSequence: expectedSequence - 1,
    headHash: expectedPreviousHash,
  };
}

export async function pruneAuditEventsBefore(
  db: D1Database,
  accountId: string,
  cutoff: string,
): Promise<number> {
  await ensureAuditChainBackfilled(db, accountId);
  const verification = await verifyAuditChain(db, accountId);
  if (!verification.valid) throw new Error(`Audit integrity verification failed: ${verification.reason ?? "unknown"}`);

  const lastDeleted = await db
    .prepare(
      `SELECT chain_sequence, event_hash
       FROM security_events
       WHERE account_id = ? AND datetime(created_at) < datetime(?)
       ORDER BY chain_sequence DESC
       LIMIT 1`,
    )
    .bind(accountId, cutoff)
    .first<{ chain_sequence: number; event_hash: string }>();
  if (!lastDeleted) return 0;

  const count = await db
    .prepare(`SELECT COUNT(*) AS count FROM security_events WHERE account_id = ? AND datetime(created_at) < datetime(?)`)
    .bind(accountId, cutoff)
    .first<{ count: number }>();

  await db.batch([
    db
      .prepare(
        `INSERT INTO audit_chain_anchors (account_id, pruned_through_sequence, pruned_through_hash, updated_at)
         VALUES (?, ?, ?, datetime('now'))
         ON CONFLICT(account_id) DO UPDATE SET
           pruned_through_sequence = excluded.pruned_through_sequence,
           pruned_through_hash = excluded.pruned_through_hash,
           updated_at = datetime('now')`,
      )
      .bind(accountId, Number(lastDeleted.chain_sequence), lastDeleted.event_hash),
    db
      .prepare(`DELETE FROM security_events WHERE account_id = ? AND datetime(created_at) < datetime(?)`)
      .bind(accountId, cutoff),
  ]);

  return Number(count?.count ?? 0);
}
