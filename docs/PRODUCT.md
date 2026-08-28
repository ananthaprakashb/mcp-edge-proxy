# ContextGateway product plan

## Positioning

**ContextGateway is the policy and audit firewall for MCP traffic.**

It sits between agent clients and MCP servers and answers three questions for every call:

1. **Who is this agent?** — hashed, revocable agent credentials now; short-lived capabilities next.
2. **Is this exact MCP operation allowed?** — method/tool policy at the edge.
3. **What happened without retaining private content?** — latency, decision, status, payload size, and data-flow metadata.

This is deliberately different from a broad MCP portal/server catalog. The paid value is least-privilege agent authorization, secret custody, policy explainability, and privacy-safe observability across MCP servers a team already operates.

## Initial customer

Small AI engineering teams that have 2–20 MCP servers or private tool endpoints and need to move from demos to production without building a policy/trace control plane.

The strongest early use cases are:

- coding agents that may access only specific repo/tool operations;
- support agents that can read knowledge tools but cannot execute admin tools;
- local/private-data agents connected through a secure tunnel;
- autonomous service agents that cannot complete human OAuth flows;
- teams that need an audit trail without logging raw prompts or tool payloads.

## Proposed packaging

Pricing should stay simple during validation:

| Plan | Proposed price | Product intent |
| --- | ---: | --- |
| Local / OSS | Free | Self-hosted gateway primitives and local experimentation |
| Developer | Free | One hosted gateway, basic scoped keys, short trace retention |
| Pro | $19/month | Multiple gateways, longer trace retention, policy history, exports |
| Team | $49/month | Team/RBAC, environments, advanced retention and shared audit views |

Usage overages and enterprise controls should wait until real traffic patterns are known. The edge rate limiter is an abuse-control mechanism, not the billing meter.

## Build sequence

### Phase 1 — edge security foundation (this PR)

- Cloudflare Worker data plane;
- D1 tenant/gateway/key/trace model;
- hashed and revocable agent keys;
- exact MCP method/name policies;
- encrypted upstream auth headers;
- plan-aware edge rate limiting;
- metadata-only traces and Worker custom spans;
- internal control API.

### Phase 2 — subscription SaaS

- React dashboard;
- email/social auth;
- organizations and roles;
- Stripe Checkout + Customer Portal;
- signed Stripe webhook updates to `plan`/`subscription_status`;
- enforced gateway/key/retention entitlements;
- exact usage aggregation separate from rate limiting.

### Phase 3 — capability authorization

Integrate the `mcp-gate` security model so orchestrators can exchange a durable identity for a short-lived, single-use capability bound to an MCP method/name and, eventually, canonical tool arguments.

### Phase 4 — agent observability

- trace waterfall;
- agent → gateway → MCP server Sankey/data-flow view;
- policy-denial explanations;
- OpenTelemetry export configuration;
- latency/error baselines and anomaly alerts;
- optional content capture only through explicit per-gateway opt-in with redaction.

### Phase 5 — secure local data bridge

- guided Cloudflare Tunnel setup;
- service-token header configuration;
- health checks for private connectors;
- connector templates for local filesystem, Postgres, Git, and document stores;
- no inbound port forwarding required.

### Phase 6 — format bridge upsell

Keep ingestion out of the core proxy process. Run asynchronous conversion workers/jobs that can turn PDFs and legacy documents into deterministic Markdown/OKF bundles, attach provenance, and expose the resulting artifacts through a separate MCP server.

## Validation metrics

Before adding broad ingestion or enterprise features, measure:

- time from signup to first proxied MCP call;
- percentage of users creating a non-wildcard policy;
- number of denied calls that users identify as useful catches;
- gateways per active account;
- seven-day retained developer accounts;
- trace views per 1,000 MCP calls;
- conversion from free hosted gateway to Pro.
