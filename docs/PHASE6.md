# Phase 6 — Secret lifecycle and rotation

Phase 6 adds versioned credential storage, controlled agent-key overlap, capability signing-key rotation, and security audit events without exposing plaintext secrets.

## What changes

- existing upstream credentials are treated as encryption version `1`
- gateways record `upstream_secret_version` and `credentials_rotated_at`
- existing agent-key hashes are backfilled into `api_key_secrets` as version `1`
- agent keys can rotate with an overlap window so old and new keys coexist temporarily
- capability signing supports multiple configured generations during rotation
- security events record rotation metadata only
- no secret value is written to D1, traces, audit metadata, or dashboard responses

## Initial deployment

No new Worker secret is required for the initial Phase 6 deployment. Existing secrets remain authoritative:

- `UPSTREAM_ENCRYPTION_KEY` = encryption version 1
- `CAPABILITY_SIGNING_KEY` = signing generation `v1`

Apply the migration before deploying:

```powershell
npm install
npm run db:migrate:remote
npm run typecheck
npm test
npm run build
npm run deploy
```

Migration: `0008_secret_lifecycle.sql`

After deployment, existing gateways and keys continue to work without rotation.

## Optional upstream encryption rotation

Generate a new 32-byte base64url key locally. Example with Node:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

Do not share the generated key in chat, source control, D1, or logs.

Create the optional Worker secret:

```powershell
npx wrangler secret put UPSTREAM_ENCRYPTION_KEYRING
```

Enter JSON like this when prompted:

```json
{"active":2,"keys":{"2":"<NEW_BASE64URL_32_BYTE_KEY>"}}
```

The original `UPSTREAM_ENCRYPTION_KEY` automatically remains version 1. Do not copy it into the keyring.

Once version 2 is active:

- newly created gateways use v2
- explicit gateway credential rotations use v2
- existing v1 gateways continue to decrypt using the original `UPSTREAM_ENCRYPTION_KEY`

Keep every encryption version configured until no gateway references it. The dashboard shows each gateway's stored encryption version.

## Optional capability signing rotation

Create a new high-entropy signing secret (at least 32 characters), then set:

```powershell
npx wrangler secret put CAPABILITY_SIGNING_KEYRING
```

Enter JSON like:

```json
{"active":"v2","keys":{"v2":"<NEW_SIGNING_SECRET>"}}
```

The original `CAPABILITY_SIGNING_KEY` automatically remains generation `v1`.

New capabilities are signed with the active generation. Incoming capabilities are checked against all configured generations. Keep the previous signing generation configured for at least the maximum capability TTL (5 minutes) plus deployment propagation time before retiring it.

## Agent-key rotation

In the dashboard:

1. Open **Team**.
2. Scroll to **Credential lifecycle**.
3. Load the gateway's credential history.
4. Choose an overlap window. Default is 300 seconds.
5. Select **Rotate key**.
6. Copy the newly generated `cg_live_*` key immediately.

The new key is valid immediately. The previous generation remains valid until the overlap expires. An overlap of `0` invalidates the previous generation immediately.

The logical API key remains the same object, so:

- policy rules are unchanged
- execution mode is unchanged
- capability parent-key identity is unchanged
- usage and plan resource counts are unchanged

Revoking the logical agent key revokes every secret generation immediately.

## Gateway credential rotation

Under **Credential lifecycle**, enter replacement upstream credentials and rotate them in place. For `cloudflare_access` gateways, provide a complete replacement Access Client ID and Client Secret pair.

The API replaces the encrypted credential envelope and records:

- encryption version
- rotation timestamp
- connection mode
- whether credentials are present

It never returns the plaintext credential after submission.

## APIs

```text
GET  /v1/app/workspaces/:workspaceId/security
POST /v1/app/workspaces/:workspaceId/gateways/:gatewayId/credentials/rotate
POST /v1/app/workspaces/:workspaceId/gateways/:gatewayId/keys/:keyId/rotate
```

Example key rotation request:

```json
{"overlapSeconds":300}
```

The response returns the new plaintext agent key exactly once.

## Audit events

`security_events` records lifecycle metadata such as:

- `gateway_credentials_rotated`
- `agent_key_rotated`
- target ID
- actor user ID
- version
- overlap duration
- previous-generation expiry
- timestamp

Secret values, hashes, ciphertext, IVs, capability tokens, and upstream headers are excluded.

## Safe rollback / retirement rules

### Encryption keys

Do not remove an old encryption version while any gateway's `upstream_secret_version` references it. Removing it first makes those stored credentials undecryptable.

### Capability signing keys

Do not remove an old signing generation until all capabilities signed by it have expired. ContextGateway's maximum capability TTL remains 300 seconds.

### Agent key generations

Agent-key overlap is stored in D1. No Worker secret change is required. After `valid_until`, the old `cg_live_*` value stops authenticating automatically.

## Validation checklist

1. Deploy Phase 6 without new keyring secrets.
2. Run `npm run smoke:capability-required`; it must still pass.
3. Verify Credential lifecycle reports encryption `v1` and signing `v1`.
4. Rotate one agent key with a 300-second overlap.
5. Verify both old and new keys can mint capabilities during overlap.
6. Verify the old key fails after the overlap expires.
7. Verify the new key continues to work.
8. Revoke the logical key and verify all generations fail.
9. Optionally activate encryption v2 and rotate one gateway's upstream credentials.
10. Verify MCP traffic still reaches the upstream.
11. Optionally activate signing v2, mint a capability, and verify both old in-flight and new capabilities during the transition.
12. Confirm Security audit events contain metadata only.
