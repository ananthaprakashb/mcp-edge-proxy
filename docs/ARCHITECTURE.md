# ContextGateway architecture

## Product boundary

ContextGateway is an MCP-aware policy enforcement point and trace plane. It is intentionally narrower than a general API gateway and narrower than an MCP server lifecycle platform.

```text
AI client / autonomous agent
          |
          | Bearer cg_live_* key
          | MCP request
          v
+------------------------------+
| ContextGateway Worker        |
|                              |
| 1. hash + resolve agent key  |
| 2. resolve tenant/gateway    |
| 3. inspect Mcp-Method/Name   |
| 4. policy decision           |
| 5. plan-aware rate limit     |
| 6. inject upstream secrets   |
| 7. emit privacy-safe trace   |
+------------------------------+
          |
          | no caller credential
          | configured upstream auth only
          v
MCP server / secure tunnel hostname
```

## Why the 2026 MCP protocol matters

The MCP 2026-07-28 protocol is stateless and carries method/tool routing metadata in HTTP headers. ContextGateway therefore does not need sticky sessions or deep JSON inspection for current clients. For compatibility with older Streamable HTTP clients, the MVP can fall back to reading JSON-RPC `method` and `params.name` from a cloned request.

## Data plane

`POST /v1/mcp/:gatewayId` is the data-plane endpoint. The Worker:

1. resolves the gateway in D1;
2. hashes the presented agent key and looks up the non-revoked key;
3. verifies account subscription state;
4. evaluates exact `allowedMethods` and `allowedNames` rules;
5. applies a Cloudflare Rate Limiting binding keyed by account/key/gateway;
6. decrypts configured upstream headers with AES-GCM;
7. strips caller credentials and forwards the MCP request as a stream;
8. returns the upstream response as a stream;
9. asynchronously writes metadata-only trace data to D1.

Cloudflare's Rate Limiting binding is used for abuse protection, not exact subscription accounting. Exact monthly usage/billing metering belongs in the control plane and should be backed by an analytics/usage pipeline.

## Control plane

The initial control plane is an internal API protected by `CONTROL_PLANE_TOKEN`:

- create account;
- create gateway;
- issue scoped agent key;
- revoke agent key;
- update subscription state;
- query recent traces.

The production SaaS dashboard will replace direct use of this token with user authentication, organizations/roles, and billing webhooks.

## Secret custody

The first hosted version uses envelope-like application encryption: one Worker secret encrypts each gateway's header map with a fresh AES-GCM IV. This is intentionally separated behind helper functions so a later version can replace it with KMS-backed envelope encryption without changing the data plane.

For local/private deployments, `mcp-gate` remains the stronger primitive for short-lived, single-use capability tokens. A later ContextGateway phase should mint or coordinate those capabilities instead of turning this edge repository into a second implementation of the same primitive.

## Observability

Two layers are emitted:

- Cloudflare Worker traces/custom spans for infrastructure-level debugging and OpenTelemetry export;
- ContextGateway's metadata trace ledger for tenant-facing product UX.

Default tenant traces never contain request bodies, response bodies, prompt content, tool arguments, or upstream credentials.
