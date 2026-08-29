# Phase 9 — Gateway health and operational diagnostics

Phase 9 adds privacy-safe connectivity checks for ContextGateway upstreams without executing MCP tools or consuming customer MCP request quota.

## Health model

Each enabled gateway has one current health state:

- `unknown` — no check has completed yet
- `healthy` — the upstream is reachable and did not return an auth/server failure
- `degraded` — upstream server/rate-limit/credential-decrypt/redirect behavior needs attention
- `unreachable` — DNS could not resolve or the network connection failed
- `auth_failure` — upstream returned HTTP 401/403 to the configured credential set
- `dns_blocked` — Phase 7 network policy rejected the configured or redirected target
- `timeout` — the upstream did not answer within the health probe timeout
- `tls_failure` — the outbound fetch failed with a TLS/certificate-class error

The gateway also records:

- last check time
- last success time
- last failure time
- last latency
- last HTTP status
- last reason
- consecutive failure count

## Safe probe sequence

A probe performs:

1. Parse the configured upstream URL.
2. Run the same Phase 7 double DNS/SSRF validation used by the MCP data plane.
3. Decrypt the gateway's configured upstream headers using the stored secret version.
4. Send an authenticated `HEAD` request with `redirect: manual` and an 8-second timeout.
5. If a redirect is returned, validate the target using Phase 7 policy but never follow it.
6. Persist only status metadata and resolved IPs.

Health probes never:

- send an MCP JSON-RPC `POST`
- execute a tool/resource/prompt operation
- consume monthly MCP request quota
- retain upstream response bodies
- retain credential/header values
- retain prompts or MCP arguments

An HTTP 405 response is considered `healthy` with reason `reachable_head_not_supported`: it proves connectivity but does not claim the upstream supports health-specific HEAD behavior.

## Scheduled checks

Wrangler config contains two Cron triggers:

```json
"triggers": {
  "crons": [
    "*/15 * * * *",
    "17 8 * * *"
  ]
}
```

- `*/15 * * * *` — bounded health probe batch
- `17 8 * * *` — existing Phase 8 daily retention lifecycle

The scheduled health pass selects the six enabled gateways with the oldest `last_health_checked_at`. This naturally forms a round-robin queue without a separate cursor table.

Six is intentionally conservative for Workers Free. Each gateway may require four Cloudflare DNS-over-HTTPS subrequests (two A/AAAA resolution passes) plus one upstream HEAD request.

## Health history

`gateway_health_checks` stores recent operational samples:

- trigger type (`manual` or `scheduled`)
- status and reason
- connection mode
- HTTP status
- latency
- resolved DNS addresses
- check time

No response body or secret values are stored.

History is bounded to the latest 672 checks per gateway to prevent unbounded D1 growth.

## Audit events

Health transitions use the existing Phase 8 tamper-evident `security_events` chain.

Events:

- `gateway_health_failed`
- `gateway_health_recovered`
- `gateway_credentials_invalid`

Repeated checks in the same state do not emit duplicate transition events.

## Dashboard/API

Read health details:

```text
GET /v1/app/workspaces/:workspaceId/gateways/:gatewayId/health
```

All workspace members can read health metadata.

Run a manual check:

```text
POST /v1/app/workspaces/:workspaceId/gateways/:gatewayId/health/check
```

Only owners/admins can trigger a manual probe.

The Team/operations area includes a minimal Gateway health & diagnostics panel. Broader placement and visual redesign remain deferred to the final UX phase.

## Deployment

After merge:

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

Migration:

```text
0010_gateway_health.sql
```

No new Worker secret is required.

## Production validation

1. Run the existing data-plane regression:

```powershell
npm run smoke:capability-required
```

2. Open **Team → Gateway health & diagnostics**.
3. Select an existing public gateway and click **Test connection**.
4. Confirm a result appears with status/reason/latency/HTTP/DNS details.
5. Confirm the gateway's MCP quota did not increment from the diagnostic request.
6. Repeat against a gateway with intentionally invalid upstream credentials if available; expect `auth_failure` only when the upstream returns 401/403 to HEAD.
7. For an unreachable test hostname, expect `unreachable` or `timeout` depending on failure mode.
8. Confirm `gateway_health_failed`, `gateway_health_recovered`, and `gateway_credentials_invalid` appear only on matching state transitions.
9. Confirm Cloudflare shows both Cron triggers after deployment.

## Important limitation

A HEAD health probe validates reachability and any authentication enforced on HEAD. An upstream that returns 405 before evaluating credentials is reported as reachable (`healthy / reachable_head_not_supported`), not as proof that MCP POST credentials are valid. ContextGateway deliberately does not send synthetic MCP tool calls merely to test credentials, because diagnostics must not cause side effects.
