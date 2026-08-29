# Phase 8 — Durable audit and retention lifecycle

Phase 8 separates short-lived troubleshooting traces from longer-lived security audit history, adds tamper-evident audit chaining, and enforces retention automatically through a Cloudflare Worker Cron Trigger.

## Retention by plan

| Plan | Trace retention | Security audit retention |
| --- | ---: | ---: |
| Free | 7 days | 30 days |
| Pro | 30 days | 90 days |
| Team | 90 days | 365 days |

The values live in `src/entitlements.ts` and are enforced by the backend, not the dashboard.

## Scheduled cleanup

Wrangler config installs this UTC Cron Trigger:

```json
"triggers": {
  "crons": ["17 8 * * *"]
}
```

The Worker `scheduled()` handler runs the same retention engine used by the authenticated manual cleanup API. Each account is processed independently.

Cleanup order per account:

1. remove traces older than the plan trace-retention window;
2. seal/backfill any legacy security events that predate Phase 8;
3. verify the retained audit hash chain;
4. if verification fails, do **not** delete audit events;
5. if verification passes, persist a chain anchor and delete audit events outside retention;
6. append a `retention_cleanup_completed` audit event;
7. persist run telemetry in `retention_runs`.

A trace cleanup can still complete even if audit integrity fails; audit deletion fails closed.

## Tamper-evident audit chain

`security_events` gains:

- `chain_sequence`
- `previous_hash`
- `event_hash`

The event hash is SHA-256 over canonical immutable event fields including sequence and previous hash. Existing events are sealed in chronological order before a new event is appended or verification is requested.

### Retention anchors

Deleting the oldest events would otherwise break the chain. Before a retained prefix is pruned, ContextGateway stores the last deleted sequence and hash in `audit_chain_anchors`.

Verification starts from that anchor and checks every remaining event forward. This preserves verifiability across retention boundaries.

This mechanism is tamper-evident inside ContextGateway storage. It is not an external notarization or digital signature service.

## APIs

### List/filter audit history

```text
GET /v1/app/workspaces/:workspaceId/audit
```

Optional query parameters:

- `eventType`
- `targetType`
- `actorUserId`
- `from`
- `to`
- `limit` (max 500)

### Export audit history

Owner/admin only:

```text
GET /v1/app/workspaces/:workspaceId/audit/export?format=csv
GET /v1/app/workspaces/:workspaceId/audit/export?format=json
```

Exports use the same filters and are capped at 5,000 rows per request.

### Verify chain

```text
GET /v1/app/workspaces/:workspaceId/audit/verify
```

### Retention/storage status

```text
GET /v1/app/workspaces/:workspaceId/retention
```

Returns plan policy, retained row counts, oldest retained timestamps, integrity state, and the latest cleanup run.

### Manual cleanup

Owner/admin only:

```text
POST /v1/app/workspaces/:workspaceId/retention/run
```

This is intended for operational validation and incident recovery. It applies the same plan policy as Cron and does not accept custom retention days.

## Migration

Apply:

```powershell
npm run db:migrate:remote
```

Migration:

```text
0009_audit_retention.sql
```

No new Worker secret is required.

## Deployment validation

```powershell
git checkout main
git pull
npm install
npm run db:migrate:remote
npm run typecheck
npm test
npm run build
npm run deploy
```

Then validate the existing data plane:

```powershell
npm run smoke:capability-required
```

In the dashboard open **Team → Credential lifecycle → Audit retention & integrity**.

Expected on first load:

- policy reflects the current plan;
- integrity shows `Verified`;
- historical security events receive chain sequence/hash metadata;
- no rows are deleted unless they are older than the applicable policy.

Run **Run cleanup** once. With a new installation it is normal for deleted counts to be zero. A `retention_cleanup_completed` event should appear and the last-run status should become `completed`.

## Local Cron validation

Cloudflare supports local scheduled-handler testing through Wrangler:

```powershell
npm run dev:scheduled
```

Then invoke the scheduled endpoint exposed by Wrangler. Current Cloudflare documentation describes `/cdn-cgi/handler/scheduled?format=json`; Wrangler versions may also expose `/__scheduled` when `--test-scheduled` is used.

## Privacy

Audit export and cleanup never add request bodies, prompts, MCP arguments, capability tokens, upstream credentials, API keys, ciphertext, or upstream headers to the audit record. Retention telemetry contains counts, policy durations, run identifiers, status and timestamps only.
