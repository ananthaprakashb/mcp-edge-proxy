# Phase 10 — Governed document / OKF context ingestion

Phase 10 lets ContextGateway govern what trusted organizational context an MCP agent may see, in addition to governing which tools it may execute.

## Scope

Supported ingestion formats:

- JSON
- YAML
- Markdown
- plain text
- OKF-style structured JSON/YAML objects

Each document is normalized before retrieval:

- JSON/YAML/OKF remain structured JSON-compatible values
- Markdown becomes `/intro` plus `/sections/<heading-slug>/{heading,level,text}`
- text becomes `/text`

The raw source is stored for provenance/versioning but is not returned by the built-in MCP document tools. Phase 10 caps each source document at 256 KiB.

## Versioning and provenance

Documents use a workspace-scoped logical `documentKey`.

- first content for a key becomes version 1
- changed content under the same key creates version 2, 3, ...
- the previous active version is marked superseded
- exact source-byte duplicates are rejected by SHA-256 hash
- each version stores format, schema name/version, source label, effective/expiry dates, byte size and content hash

## Fail-closed access policies

A stored document is not readable by an agent until at least one explicit `context_document_policies` row matches.

A policy may be scoped to:

- a gateway
- an individual agent key
- both

The API supports account-wide explicit policies by omitting gateway/key, but the dashboard creates gateway-scoped policies by default.

Policy fields:

- `allowedOperations`: `read`, `list`
- `allowedPaths`: `*`, exact JSON-pointer paths such as `/public/name`, or subtree paths such as `/public/*`

If a policy allows only `/public/*`, requesting the full document is denied.

## Built-in MCP tools

ContextGateway intercepts these tool names on the normal endpoint:

```text
POST /v1/mcp/:gatewayId
```

### List authorized documents

```text
method: tools/call
name: contextgateway.document.list
arguments: {}
```

Only effective, non-expired documents with a matching `list` policy are returned. The response contains metadata/provenance only.

### Read authorized content

```text
method: tools/call
name: contextgateway.document.read
arguments:
  documentKey: employee-handbook
  path: /public/benefits
```

`path` is optional only when the matching document policy includes `*`.

Document reads require:

1. a valid `cg_cap_*` token
2. capability account/gateway/key/method/name match
3. current parent agent key still active
4. current key policy allows `tools/call` + `contextgateway.document.read`
5. capability arguments SHA-256 binding to the exact `documentKey` and `path`
6. document is effective and not expired
7. matching document gateway/key policy
8. requested path allowed
9. request rate/quota available
10. atomic single-use capability consumption

A long-lived `cg_live_*` key can mint the capability but cannot directly read governed context.

## Agent key scopes

Create or use a capability-required key whose policy includes:

```text
Allowed methods:
tools/call

Allowed names:
contextgateway.document.list, contextgateway.document.read
```

For a read capability, mint with the exact arguments:

```json
{
  "method": "tools/call",
  "name": "contextgateway.document.read",
  "ttlSeconds": 30,
  "arguments": {
    "documentKey": "phase10-demo",
    "path": "/public/message"
  }
}
```

## Retrieval audit

Every governed `list` or `read` stores metadata in `context_document_access_log`:

- document key/version/hash
- gateway and agent key IDs
- operation
- requested path
- allow/deny decision
- reason
- capability JTI
- timestamp

It never stores the returned document value.

Denied reads additionally append `context_document_access_denied` into the Phase 8 tamper-evident security-event chain.

Management/security events:

- `context_document_ingested`
- `context_document_policy_granted`
- `context_document_policy_revoked`
- `context_document_access_denied`

## Management APIs

```text
POST /v1/app/workspaces/:workspaceId/documents/validate
GET  /v1/app/workspaces/:workspaceId/documents
POST /v1/app/workspaces/:workspaceId/documents
GET  /v1/app/workspaces/:workspaceId/documents/:documentKey
GET  /v1/app/workspaces/:workspaceId/documents/:documentKey/policies
POST /v1/app/workspaces/:workspaceId/documents/:documentKey/policies
DELETE /v1/app/workspaces/:workspaceId/documents/:documentKey/policies/:policyId
GET  /v1/app/workspaces/:workspaceId/documents/:documentKey/access
```

Owners/admins manage ingestion/policies. Workspace members may view governed-context metadata and access history.

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
0011_governed_context.sql
```

No new Worker secret or Cloudflare paid feature is required.

## Production validation

### 1. Regression

```powershell
npm run smoke:capability-required
```

### 2. Create a safe synthetic document

Open **Team → Governed context** and ingest:

```text
Document key: phase10-demo
Title: Phase 10 synthetic demo
Format: JSON
Source: synthetic-production-validation
Allowed gateway: your existing public test gateway
Allowed paths: /public/*
```

Content:

```json
{
  "public": {
    "message": "ContextGateway governed context works",
    "supportTier": "standard"
  },
  "private": {
    "internalNote": "must not be returned through the public policy"
  }
}
```

Click **Validate**, then **Ingest**.

### 3. Create/choose a key

Use a capability-required key on the same gateway with:

```text
allowedMethods: tools/call
allowedNames: contextgateway.document.read, contextgateway.document.list
```

### 4. Run the positive/replay smoke

PowerShell:

```powershell
$env:CONTEXTGATEWAY_BASE_URL = "https://contextgateway-edge.subhafash-86.workers.dev"
$env:GATEWAY_ID = "YOUR_GATEWAY_ID"
$env:AGENT_KEY = "YOUR_CONTEXT_CAPABLE_CG_LIVE_KEY"
$env:CONTEXT_DOCUMENT_KEY = "phase10-demo"
$env:CONTEXT_DOCUMENT_PATH = "/public/message"

npm run smoke:context
```

Expected:

```text
✓ governed document reads reject direct cg_live_* execution
✓ generic/unbound capabilities cannot read governed documents
✓ exact documentKey/path capability minted
✓ governed context returned phase10-demo/public/message with provenance hash
✓ governed context capability remains single-use
PASS
```

### 5. Validate redaction/fail-closed behavior

Mint a new arguments-bound capability for:

```text
/private/internalNote
```

The read must return HTTP 403 `document_access_denied` because the policy only grants `/public/*`.

Open **Policies & access** for `phase10-demo`. The denied operation should appear with path, reason, key/gateway metadata and capability JTI, but not the private value.

### 6. Validate versioning

Change the public message and ingest again with the same `phase10-demo` key.

Expected active document:

```text
version 2
```

The document detail API retains version 1 metadata as superseded.

Trying to ingest byte-for-byte identical content should return `duplicate_document` rather than creating another version.

## Intentional Phase 10 boundaries

This phase does not yet add:

- PDFs/binary extraction
- R2 object storage
- embeddings/vector search
- semantic chunking/RAG
- document OCR
- external connectors

Those should be added only after the governed storage/access model is proven. The current 256 KiB D1-backed model keeps the security boundary simple and testable on Workers Free.
