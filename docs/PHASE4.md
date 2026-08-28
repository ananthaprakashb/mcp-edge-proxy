# Phase 4 — Private MCP connectivity and OpenTelemetry export

Phase 4 moves ContextGateway from public-only upstreams toward production internal MCP services while preserving the existing capability, policy, quota, and trace pipeline.

## What changed

### Cloudflare Tunnel + Access upstreams

A gateway now has one of two connection modes:

- `public` — existing HTTPS upstream behavior.
- `cloudflare_access` — an HTTPS hostname published through Cloudflare Tunnel and protected by Cloudflare Access Service Auth.

For `cloudflare_access`, ContextGateway accepts a Cloudflare Access Client ID and Client Secret at gateway creation time. They are merged into the upstream header envelope, encrypted with the existing `UPSTREAM_ENCRYPTION_KEY`, and never returned by dashboard/API reads.

At execution time ContextGateway strips caller-supplied `CF-Access-Client-Id` / `CF-Access-Client-Secret` headers and injects the stored encrypted values immediately before forwarding.

No new Worker secret is required.

### Privacy-safe OpenTelemetry spans

The Worker already uses Cloudflare custom spans. Phase 4 adds bounded attributes that can be exported through Cloudflare's native OTLP destinations:

- `contextgateway.gateway.id`
- `contextgateway.auth.mode`
- `contextgateway.key.execution_mode`
- `contextgateway.upstream.mode`
- `contextgateway.policy.decision`
- `contextgateway.policy.reason`
- `contextgateway.policy.method_rule`
- `contextgateway.policy.name_rule`
- `mcp.method.name`
- `mcp.name`
- `http.response.status_code`

The OTel span deliberately excludes:

- agent-key values
- capability-token values
- capability JTI
- Access service-token credentials
- upstream headers
- account/user identity
- request or response bodies
- prompts
- MCP arguments
- upstream URL

D1 Trace Explorer remains independent from Cloudflare OTel sampling/export.

## Deploy Phase 4

```bash
npm install
npm run db:migrate:remote
npm run typecheck
npm test
npm run build
npm run deploy
```

Migration:

```text
0006_private_connectivity.sql
```

Existing gateways become `public` automatically.

## End-to-end private connectivity validation

### 1. Run the included private MCP echo origin

In a terminal on a machine where you can run `cloudflared`:

```bash
npm run private:echo
```

It listens only on loopback:

```text
http://127.0.0.1:8789/mcp
```

### 2. Create a Cloudflare Tunnel

In Cloudflare Dashboard:

1. Go to **Networking → Tunnels**.
2. Create a tunnel and install/run the generated `cloudflared` connector on the same machine or a machine that can reach the private origin.
3. Add a **Published application** route.
4. Choose a hostname such as `private-mcp.example.com`.
5. Set its service to `http://127.0.0.1:8789`.

The origin itself does not need a public IP or inbound firewall port; `cloudflared` establishes outbound connections to Cloudflare.

### 3. Protect the hostname with Cloudflare Access

In **Zero Trust → Access controls → Applications**:

1. Create a self-hosted/private application for the published hostname.
2. Create a **Service Token** under **Access controls → Service credentials → Service Tokens**.
3. Save the generated Client ID and Client Secret; the secret is shown only at creation/rotation time.
4. Add a **Service Auth** policy to the Access application that includes that service token.

Do not put the service token in source control.

### 4. Create a ContextGateway private gateway

Create a gateway using:

```json
{
  "name": "private-tunnel-validation",
  "upstreamUrl": "https://private-mcp.example.com/mcp",
  "connectionMode": "cloudflare_access",
  "accessClientId": "<CF Access Client ID>",
  "accessClientSecret": "<CF Access Client Secret>",
  "upstreamHeaders": {}
}
```

The application API endpoint is:

```text
POST /v1/app/workspaces/:workspaceId/gateways
```

Use the dashboard once the Phase 4 gateway form is available, or call the authenticated application API from a trusted admin client.

Issue a capability-required key that permits:

```text
method: tools/call
name: demo.allowed
```

### 5. Run the smoke test

```bash
export CONTEXTGATEWAY_BASE_URL="https://contextgateway-edge.example.workers.dev"
export GATEWAY_ID="..."
export AGENT_KEY="cg_live_..."
export MCP_METHOD="tools/call"
export MCP_NAME="demo.allowed"

npm run smoke:private-access
```

PowerShell:

```powershell
$env:CONTEXTGATEWAY_BASE_URL = "https://contextgateway-edge.example.workers.dev"
$env:GATEWAY_ID = "..."
$env:AGENT_KEY = "cg_live_..."
$env:MCP_METHOD = "tools/call"
$env:MCP_NAME = "demo.allowed"

npm run smoke:private-access
```

Expected:

```text
✓ capability minted for private gateway
✓ Access-protected Tunnel upstream reached: HTTP 200
✓ response confirms cloudflare_access upstream mode
✓ execution used a short-lived capability
PASS: Phase 4 private MCP connectivity works through Cloudflare Tunnel + Access.
```

Never paste the Access Client Secret or `cg_live_*` key into an issue, PR, or chat.

## Configure native OpenTelemetry export

Cloudflare Workers Observability can export Worker traces/logs to an OTLP-compatible destination. Destination credentials live in Cloudflare's Observability destination configuration rather than ContextGateway/D1.

### 1. Create a trace destination

Go to your Cloudflare account's **Workers Observability** page and add a destination:

```text
Name: contextgateway-traces
Type: Traces
Endpoint: your provider's OTLP traces endpoint
Headers: provider authentication headers
```

Examples include Grafana Cloud, Honeycomb, Axiom, and Sentry.

### 2. Attach it to ContextGateway

After the destination exists, update the existing `observability.traces` section of `wrangler.jsonc`:

```jsonc
"observability": {
  "enabled": true,
  "traces": {
    "enabled": true,
    "destinations": ["contextgateway-traces"],
    "head_sampling_rate": 0.1
  }
}
```

Choose a sampling rate appropriate for production traffic. D1 Trace Explorer is not sampled by this setting.

Then redeploy:

```bash
npm run deploy
```

Do not add a destination name to `wrangler.jsonc` before that destination exists in the Cloudflare account, because deployment may reject an unresolved destination.

### 3. Validate exported attributes

Execute a capability call and confirm the external trace contains the `contextgateway.*` attributes above. It must not contain credentials, MCP arguments, prompt text, or request/response bodies added by ContextGateway.

## Workers VPC path

Cloudflare Workers VPC can route Worker `fetch()` calls directly to VPC Service bindings backed by Cloudflare Tunnel and gives stronger service-level SSRF isolation. It is currently a beta capability and Worker bindings are static deployment configuration.

That makes it a good future option for dedicated/enterprise ContextGateway deployments. The current `cloudflare_access` mode is more practical for the multi-tenant SaaS control plane because gateways can be created dynamically without redeploying the Worker for each private service.

## Security notes

- The tunnel hostname is still a public DNS name, but the private origin has no public listener and Cloudflare Access denies requests that do not satisfy the Service Auth policy.
- Enable **Protect with Access** / token validation in the Tunnel or validate Access at the origin when appropriate so a networking mistake cannot bypass Access.
- Rotate Access service tokens periodically. Phase 4 stores their values encrypted, but automated rotation/update UX is a later credential-lifecycle phase.
- Current URL validation still blocks literal loopback/private/link-local targets from ordinary Worker `fetch()` calls. A Tunnel hostname remains the intended route for this connection mode.
- Workers VPC should be preferred later where a dedicated static service binding is operationally acceptable.
