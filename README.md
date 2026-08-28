# ContextGateway

**A privacy-first security and observability gateway for Model Context Protocol traffic.**

ContextGateway sits between AI agents and MCP servers. It gives each agent a revocable, scoped credential, enforces MCP method/tool policy at the edge, keeps upstream credentials outside model context, and records a metadata-only audit trace for every decision.

This repository is the hosted edge/control-plane foundation for the `ContextGateway` Micro-SaaS. The existing [`mcp-gate`](https://github.com/ananthaprakashb/mcp-gate) project remains the focused local primitive for short-lived, single-use capability tokens.

## Why now

The MCP `2026-07-28` specification made the protocol stateless and added `Mcp-Method` and `Mcp-Name` HTTP routing metadata. That makes it practical for an edge gateway to perform policy decisions without sticky sessions or deep packet inspection.

ContextGateway focuses on the layer that remains application-specific:

- which agent identity can call which MCP method/tool;
- how upstream credentials stay outside agent context;
- how private MCP servers are reached through secure connectivity;
- how teams audit agent activity without retaining prompts or tool bodies.

## MVP capabilities

- **Scoped agent keys** — random `cg_live_*` keys stored only as SHA-256 hashes.
- **MCP-aware authorization** — exact allowlists for `Mcp-Method` and `Mcp-Name`, with a standalone `*` wildcard.
- **Secret custody** — upstream auth headers are AES-256-GCM encrypted in D1 and injected only at forwarding time.
- **Caller credential stripping** — inbound bearer tokens, cookies, proxy auth, and Cloudflare Access service-token headers are never blindly passed upstream.
- **Plan-aware abuse protection** — Cloudflare Workers Rate Limiting bindings for free vs. paid traffic classes.
- **Privacy-safe traces** — method/name, policy decision, status, latency, and sizes when available; no MCP bodies by default.
- **Cloudflare tracing** — custom Worker spans can flow through Cloudflare's OpenTelemetry export path.
- **Subscription-ready data model** — plan, subscription status, and billing identifiers are separated from request authorization.
- **Secure private connectivity path** — encrypted arbitrary upstream headers support tunneled MCP servers, including service-token style authentication.

See [docs/PRODUCT.md](docs/PRODUCT.md) for the product/monetization sequence and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the technical boundary.

## Architecture

```text
Agent / MCP client
      |
      | cg_live_* + MCP request
      v
Cloudflare Worker
  ├─ hash key + tenant lookup (D1)
  ├─ method/tool policy decision
  ├─ plan-aware edge rate limit
  ├─ decrypt + inject upstream headers
  ├─ custom infrastructure span
  └─ metadata-only product trace (D1)
      |
      v
MCP server or secure tunnel hostname
```

## Local setup

Requires Node.js 22+ and a Cloudflare account for remote deployment.

```bash
npm install
npx wrangler d1 create contextgateway
```

Replace the placeholder `database_id` in `wrangler.jsonc` with the ID returned by Cloudflare, then apply the schema locally:

```bash
npm run db:migrate:local
```

Create local development secrets in `.dev.vars`:

```text
CONTROL_PLANE_TOKEN=replace-with-a-long-random-control-token
UPSTREAM_ENCRYPTION_KEY=replace-with-a-base64url-encoded-32-byte-key
```

Generate an encryption key with Python:

```bash
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))"
```

Then run:

```bash
npm run dev
```

## Create a gateway

The Phase 1 control API uses one internal bearer token. User login/RBAC and Stripe webhooks are Phase 2.

Create an account:

```bash
curl -sS http://localhost:8787/v1/control/accounts \
  -H "Authorization: Bearer $CONTROL_PLANE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Acme AI","plan":"free"}'
```

Create a gateway to an HTTPS MCP endpoint:

```bash
curl -sS http://localhost:8787/v1/control/gateways \
  -H "Authorization: Bearer $CONTROL_PLANE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "accountId":"ACCOUNT_ID",
    "name":"private-tools",
    "upstreamUrl":"https://mcp.example.com/mcp",
    "upstreamHeaders":{"Authorization":"Bearer upstream-secret"}
  }'
```

For a private service behind Cloudflare Access/Tunnel, `upstreamHeaders` can instead hold the required service-token headers. Those values are encrypted before D1 storage.

Issue an agent key restricted to one MCP operation:

```bash
curl -sS http://localhost:8787/v1/control/keys \
  -H "Authorization: Bearer $CONTROL_PLANE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "accountId":"ACCOUNT_ID",
    "gatewayId":"GATEWAY_ID",
    "name":"coding-agent",
    "allowedMethods":["tools/list","tools/call"],
    "allowedNames":["github.create_issue","github.add_comment"]
  }'
```

The plaintext agent key is returned once.

## Proxy an MCP request

For MCP 2026-07-28 clients, ContextGateway reads the standard routing headers. It also falls back to JSON-RPC `method` and `params.name` for older Streamable HTTP clients.

```bash
curl -sS http://localhost:8787/v1/mcp/GATEWAY_ID \
  -H "Authorization: Bearer $CONTEXTGATEWAY_AGENT_KEY" \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: github.create_issue' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github.create_issue","arguments":{}}}'
```

## Inspect traces

```bash
curl -sS 'http://localhost:8787/v1/control/traces?gatewayId=GATEWAY_ID&limit=50' \
  -H "Authorization: Bearer $CONTROL_PLANE_TOKEN"
```

Trace rows intentionally do not contain prompt text, MCP request bodies, tool arguments, response bodies, or upstream credentials.

## Subscription behavior

The schema currently supports `free`, `pro`, and `team` plans. Paid plans allow data-plane traffic only while the subscription is `trialing` or `active`. The internal subscription endpoint exists so billing integration can update entitlement state without mixing billing logic into the data plane:

```text
PATCH /v1/control/accounts/:accountId/subscription
```

Cloudflare's edge rate limiter is intentionally **not** used as the billable usage counter because it is an eventually consistent abuse-protection mechanism. Exact usage accounting will be added separately with the billing/dashboard phase.

## Security defaults

- HTTPS upstreams only by default.
- Obvious loopback, link-local, metadata-service, and RFC1918 IP targets are rejected in hosted mode.
- MCP bodies are forwarded as streams and are not persisted.
- Configured upstream headers are encrypted at rest in D1.
- Agent keys are hashed and can be revoked.
- Policy parsing fails closed when an MCP method cannot be identified.

Read [SECURITY.md](SECURITY.md) before deploying this as a security boundary.

## Roadmap

The next milestones are:

1. React dashboard + auth + Stripe subscriptions.
2. `mcp-gate` short-lived/single-use capability integration.
3. Sankey and trace-waterfall UI with policy explanations.
4. OpenTelemetry destination management and retention controls.
5. Guided secure local connector/Tunnel setup.
6. Separate asynchronous PDF/legacy-format → Markdown/OKF ingestion service.

## License

MIT — see [LICENSE](LICENSE).
