import { describe, expect, it } from "vitest";
import { auditEventsCsv } from "../src/audit-api";
import { auditHashPayload, canonicalJson, computeAuditEventHash } from "../src/audit-integrity";
import { getPlanEntitlements } from "../src/entitlements";
import { retentionCutoff } from "../src/retention";

describe("audit integrity helpers", () => {
  it("canonicalizes nested object keys deterministically", () => {
    expect(canonicalJson({ b: 2, a: { y: true, x: 1 } })).toBe(canonicalJson({ a: { x: 1, y: true }, b: 2 }));
  });

  it("binds event hashes to sequence and previous hash", async () => {
    const base = {
      id: "evt-1",
      accountId: "acct-1",
      workspaceId: "ws-1",
      actorUserId: "user-1",
      eventType: "agent_key_rotated",
      targetType: "api_key",
      targetId: "key-1",
      metadataJson: '{"version":2}',
      createdAt: "2026-08-29T04:00:00.000Z",
      chainSequence: 7,
      previousHash: "abc123",
    };
    const first = await computeAuditEventHash(base);
    const second = await computeAuditEventHash({ ...base, chainSequence: 8 });
    const third = await computeAuditEventHash({ ...base, previousHash: "different" });
    expect(first).not.toBe(second);
    expect(first).not.toBe(third);
    expect(auditHashPayload(base)).toContain('"chainSequence":7');
  });
});

describe("retention policy", () => {
  it("uses the intended plan retention windows", () => {
    expect(getPlanEntitlements("free")).toMatchObject({ traceRetentionDays: 7, auditRetentionDays: 30 });
    expect(getPlanEntitlements("pro")).toMatchObject({ traceRetentionDays: 30, auditRetentionDays: 90 });
    expect(getPlanEntitlements("team")).toMatchObject({ traceRetentionDays: 90, auditRetentionDays: 365 });
  });

  it("computes a cutoff from an explicit clock", () => {
    const now = Date.parse("2026-08-29T08:17:00.000Z");
    expect(retentionCutoff(now, 7)).toBe("2026-08-22T08:17:00.000Z");
  });
});

describe("audit export", () => {
  it("quotes commas quotes and newlines in CSV", () => {
    const csv = auditEventsCsv([{
      id: "evt-1",
      event_type: "test,event",
      actor_name: 'A "User"',
      actor_email: "a@example.com",
      target_type: "gateway",
      target_id: "gw-1",
      metadata_json: "{\n\"ok\":true\n}",
      chain_sequence: 1,
      previous_hash: null,
      event_hash: "hash",
      created_at: "2026-08-29T04:00:00.000Z",
    }]);
    expect(csv).toContain('"test,event"');
    expect(csv).toContain('"A ""User"""');
    expect(csv).toContain('"{\n""ok"":true\n}"');
  });
});
