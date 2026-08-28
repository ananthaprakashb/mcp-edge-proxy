# Phase 3 — MCP single-use capabilities

Phase 3 integrates the core authorization idea from [`mcp-gate`](https://github.com/ananthaprakashb/mcp-gate) into the managed ContextGateway data plane.

The trusted orchestrator keeps the reusable `cg_live_*` gateway key. It exchanges that key for a narrowly scoped `cg_cap_*` capability and gives only the capability to the model/tool executor.

```text
Trusted orchestrator
  | holds cg_live_* key
  | POST /v1/mcp/:gatewayId/capabilities
  v
ContextGateway
  | verifies parent key + subscription + policy
  | signs 1–300 second capability
  v
Agent / tool executor
  | receives cg_cap_* only
  | POST /v1/mcp/:gatewayId
  v
ContextGateway
  | verify HMAC signature + expiry
  | exact gateway + MCP method + name match
  | optional exact canonical-JSON arguments digest
  | re-check parent key and policy
  | atomically consume JTI in D1
  | monthly quota + upstream forwarding
  v
MCP server
```

## Security properties

- Dedicated `CAPABILITY_SIGNING_KEY`; it is not reused for Better Auth, upstream encryption, or the control plane.
- Capability TTL defaults to 30 seconds and is capped at 300 seconds, matching `mcp-gate`'s policy ceiling.
- Each token is bound to one gateway, MCP method, and exact MCP name.
- If `arguments` are supplied during issuance, the capability commits to the SHA-256 digest of canonical JSON. Object key order does not affect the digest, but values and array order do.
- Capability JTI consumption uses a D1 primary-key insert, giving distributed replay protection across Worker isolates.
- Replay storage fails closed with HTTP 503.
- The originating `cg_live_*` key is reloaded for every capability execution. Revoking the parent key immediately invalidates outstanding capabilities.
- Current agent-key policy and subscription state are re-evaluated on capability execution.
- MCP headers and the JSON-RPC body must agree when both describe the operation.
- Upstream credentials remain server-side and are not included in capabilities.

## Migration and secret

After merging Phase 3:

```powershell
 git checkout main
 git pull
 npm install
 npm run db:migrate:remote
```

Migration `0004_capabilities.sql` creates the distributed replay table.

Generate a dedicated signing secret locally:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Store it directly in Cloudflare; do not paste it into source control or chat:

```powershell
npx wrangler secret put CAPABILITY_SIGNING_KEY
```

Then deploy:

```powershell
npm run deploy
```

## Mint a capability

Given an existing gateway ID and its active long-lived key:

```powershell
$base = "https://contextgateway-edge.subhafash-86.workers.dev"
$gatewayId = "YOUR_GATEWAY_ID"
$agentKey = "YOUR_CG_LIVE_KEY"

$mintHeaders = @{
  Authorization = "Bearer $agentKey"
}

$mintBody = @{
  method = "tools/call"
  name = "demo.allowed"
  ttlSeconds = 30
  arguments = @{
    message = "single-use capability"
    sequence = 1
  }
} | ConvertTo-Json -Depth 8

$mint = Invoke-RestMethod `
  -Uri "$base/v1/mcp/$gatewayId/capabilities" `
  -Method POST `
  -Headers $mintHeaders `
  -ContentType "application/json" `
  -Body $mintBody

$capability = $mint.access_token
```

The returned token begins with `cg_cap_` and contains no upstream credential or long-lived gateway secret.

## Execute once

```powershell
$headers = @{
  Authorization = "Bearer $capability"
  "Mcp-Method" = "tools/call"
  "Mcp-Name" = "demo.allowed"
}

$body = @{
  jsonrpc = "2.0"
  id = 1
  method = "tools/call"
  params = @{
    name = "demo.allowed"
    arguments = @{
      message = "single-use capability"
      sequence = 1
    }
  }
} | ConvertTo-Json -Depth 8

Invoke-WebRequest `
  -Uri "$base/v1/mcp/$gatewayId" `
  -Method POST `
  -Headers $headers `
  -ContentType "application/json" `
  -Body $body
```

Expected: upstream success and response header `X-ContextGateway-Auth-Mode: capability`.

Repeat the identical request with the same capability. Expected:

```text
HTTP 401
capability_replayed
```

Changing the MCP name returns `403 capability_scope_denied`. Changing argument values on an argument-bound capability returns `403 capability_arguments_denied` and does **not** consume the capability, so the exact authorized request can still be executed once.

## Automated production smoke

The repository includes a smoke script for a gateway whose upstream accepts the configured operation (the earlier `https://httpbin.org/anything` validation gateway is suitable):

```powershell
$env:CONTEXTGATEWAY_BASE_URL = "https://contextgateway-edge.subhafash-86.workers.dev"
$env:GATEWAY_ID = "YOUR_GATEWAY_ID"
$env:AGENT_KEY = "YOUR_CG_LIVE_KEY"
$env:MCP_METHOD = "tools/call"
$env:MCP_NAME = "demo.allowed"

npm run smoke:capabilities
```

Expected final line:

```text
PASS: Phase 3 short-lived, single-use, scope-bound, argument-bound capability flow works.
```

## Compatibility and next hardening

Existing `cg_live_*` keys continue to work directly so Phase 3 can be deployed without breaking clients. The recommended agent architecture is to keep those reusable credentials in a trusted orchestrator and give executors only `cg_cap_*` tokens.

After production validation, the next hardening step is an opt-in `capability_required` mode on agent keys so direct data-plane execution with the long-lived key can be disabled while still allowing that key to mint capabilities.
