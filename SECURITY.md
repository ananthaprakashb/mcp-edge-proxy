# Security

ContextGateway is a security boundary between AI agents and MCP servers. Treat changes to authentication, policy evaluation, upstream header injection, encryption, and request forwarding as security-sensitive.

## Current threat model

The hosted edge gateway is designed to reduce these risks:

- reusable upstream credentials entering model context;
- an agent invoking MCP methods or named tools outside its assigned scope;
- accidental forwarding of caller credentials to an upstream MCP server;
- sensitive MCP request/response bodies being retained in the product trace store;
- direct configuration of obvious loopback, link-local, or RFC1918 upstream targets in hosted mode.

The MVP does **not** protect against compromise of the Cloudflare account, Worker deployment credentials, the control-plane token, the D1 database plus the Worker encryption key, or the upstream MCP server itself.

## Secret handling

- Agent keys are stored only as SHA-256 hashes.
- Upstream authentication headers are encrypted with AES-256-GCM using `UPSTREAM_ENCRYPTION_KEY` before storage in D1.
- Upstream headers are decrypted only inside the Worker immediately before forwarding.
- Caller `Authorization`, cookies, proxy authorization, and Cloudflare Access service-token headers are removed before configured upstream headers are injected.
- The trace store records metadata only: method/name, decision, status, sizes when available, and latency. It does not persist MCP bodies or configured upstream headers.

For production, generate `UPSTREAM_ENCRYPTION_KEY` from 32 random bytes and keep it only as a Worker secret. Rotation/envelope encryption is planned before a general-availability hosted service.

## Private connectivity

The hosted Worker intentionally rejects obvious localhost/private-network URLs. Do not expose a private MCP server directly to the public Internet merely to connect it to ContextGateway. Use a secure tunnel or private connectivity layer and authenticate that tunnel endpoint with encrypted upstream headers.

## Reporting

Do not open a public issue for a suspected vulnerability that could expose secrets or bypass authorization. Use GitHub private vulnerability reporting when enabled for this repository.
