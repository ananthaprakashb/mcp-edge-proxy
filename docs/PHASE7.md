# Phase 7 — SSRF and DNS-rebinding hardening

Phase 7 adds a network-boundary policy in front of every public MCP upstream request.

## Goals

- reject loopback, link-local, private, CGNAT, benchmark, documentation, multicast, reserved, and cloud-metadata addresses
- validate both IPv4 and IPv6 DNS answers before contacting an upstream
- detect a public-to-private DNS change across two immediate resolution checks
- fail closed when DNS cannot be validated
- block unsafe redirects without automatically following them
- record network-security decisions as metadata-only security events
- preserve Cloudflare Tunnel + Access as a supported private-connectivity pattern without turning it into a blanket private-IP bypass

## Runtime flow

```text
MCP request
   |
   v
Gateway lookup
   |
   v
Static host/IP policy
   |
   v
Cloudflare DoH A + AAAA resolution
   |
   v
Public-address validation
   |
   v
Immediate second resolution
   |
   +---- private/rebound/failure ----> block + security event
   |
   v
Existing authentication / capability / policy / quota path
   |
   v
Existing fetch(..., redirect: "manual")
   |
   +---- unsafe Location header -----> block + security event
   |
   v
Return upstream response
```

The DNS checks use Cloudflare's public DNS-over-HTTPS endpoint. Each validation performs A and AAAA queries twice. This is intentionally fail-closed and security-first; we can optimize validated-host caching later only if we can preserve the same security properties.

## Address classes blocked

IPv4 includes:

- `0.0.0.0/8`
- `10.0.0.0/8`
- `100.64.0.0/10`
- `127.0.0.0/8`
- `169.254.0.0/16`
- `172.16.0.0/12`
- `192.0.0.0/24`
- `192.0.2.0/24`
- `192.88.99.0/24`
- `192.168.0.0/16`
- `198.18.0.0/15`
- `198.51.100.0/24`
- `203.0.113.0/24`
- multicast and reserved space

IPv6 includes:

- unspecified and loopback
- IPv4-mapped private addresses
- NAT64 representations of private/metadata IPv4 addresses
- local-use NAT64
- discard-only ranges
- benchmark and documentation ranges
- `fc00::/7`
- link-local and deprecated site-local ranges
- multicast

Known metadata targets such as `169.254.169.254`, `metadata.google.internal`, and EC2 instance-data hostnames are also blocked.

## Hostname policy

The static policy rejects local/internal names before DNS, including:

- `localhost` / `*.localhost`
- `*.local`
- `*.internal`
- `*.home.arpa`
- reserved `.invalid` and `.test` names
- known cloud metadata hostnames

## DNS rebinding

ContextGateway resolves the hostname, confirms every returned address is public, immediately resolves it again, and confirms the second answer set also contains only public addresses.

If the first result is public and the second contains a private/non-public address, the request is blocked as:

```text
upstream_dns_rebinding_blocked
```

Cloudflare Workers does not expose a general mechanism to pin `fetch()` to an arbitrary pre-resolved public IP while retaining TLS/SNI for arbitrary external domains. Therefore this mitigation reduces DNS-rebinding exposure but does not claim perfect DNS pinning. The Worker continues to use `redirect: "manual"`, which prevents an upstream 3xx from causing a server-side follow-up request.

## Redirect policy

ContextGateway does not automatically follow upstream redirects. Before returning a 3xx response, Phase 7 validates the `Location` target.

Blocked cases include:

- HTTPS to HTTP downgrade
- private/reserved/metadata targets
- internal/local hostnames
- DNS targets resolving to non-public addresses
- malformed or unsupported redirect schemes

An unsafe redirect is replaced with HTTP 502 and:

```text
upstream_redirect_blocked
```

## Security events

Phase 7 uses the existing `security_events` table. No new migration is required.

Possible event types:

- `upstream_ssrf_blocked`
- `upstream_private_ip_blocked`
- `upstream_dns_rebinding_blocked`
- `upstream_dns_validation_failed`
- `upstream_redirect_blocked`

Metadata can include:

- gateway ID
- connection mode
- hostname
- block reason
- blocked address
- up to eight resolved addresses
- whether the two DNS checks changed
- phase: `configuration`, `preflight`, or `redirect`

No request body, prompt, MCP arguments, credentials, capability token, upstream headers, or upstream URL path/query is stored.

## Cloudflare Tunnel + Access

`cloudflare_access` remains supported, but it is deliberately **not** a blanket private-address exception. The configured Tunnel hostname must still be a normal public HTTPS hostname and pass the same network validation.

The private origin remains reachable only through Cloudflare Tunnel. A future Workers VPC binding can be modeled as a separate explicit connection mode with its own constrained routing policy.

## Deployment

No new Worker secret and no D1 migration are required.

```powershell
git checkout main
git pull
npm install
npm run typecheck
npm test
npm run build
npm run deploy
```

Then run the existing production regression:

```powershell
npm run smoke:capability-required
```

## Manual validation

### Existing public gateway

Run the existing capability-required smoke. It should continue to PASS.

### Static private target

Attempt to create a gateway using one of:

```text
https://127.0.0.1/mcp
https://10.0.0.1/mcp
https://169.254.169.254/latest/meta-data/
https://[::1]/mcp
```

Creation must be rejected.

### DNS-to-private target

Use a controlled test hostname whose public DNS A/AAAA record resolves to an RFC1918 or other non-public address. Authenticated gateway creation should be rolled back and return a network-policy error.

### Audit

Open **Team → Credential lifecycle → Security audit events** and verify the block appears without any secret/request content.

## Cloudflare runtime notes

Cloudflare documents that Workers can use DNS over HTTPS and that normal `fetch()` performs its own origin resolution. `resolveOverride` cannot generally pin arbitrary external domains because it is constrained to hostnames in the Worker's zone. Phase 7 therefore uses fail-closed DNS validation plus manual redirects rather than claiming unsupported connection pinning.
