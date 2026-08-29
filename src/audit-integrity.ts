import { sha256Hex } from "./crypto";

export interface AuditHashFields {
  id: string;
  accountId: string;
  workspaceId: string | null;
  actorUserId: string | null;
  eventType: string;
  targetType: string;
  targetId: string;
  metadataJson: string;
  createdAt: string;
  chainSequence: number;
  previousHash: string | null;
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, stableValue(child)]),
    );
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(stableValue(value));
}

export function auditHashPayload(fields: AuditHashFields): string {
  return canonicalJson({
    id: fields.id,
    accountId: fields.accountId,
    workspaceId: fields.workspaceId,
    actorUserId: fields.actorUserId,
    eventType: fields.eventType,
    targetType: fields.targetType,
    targetId: fields.targetId,
    metadataJson: fields.metadataJson,
    createdAt: fields.createdAt,
    chainSequence: fields.chainSequence,
    previousHash: fields.previousHash,
  });
}

export async function computeAuditEventHash(fields: AuditHashFields): Promise<string> {
  return sha256Hex(auditHashPayload(fields));
}
