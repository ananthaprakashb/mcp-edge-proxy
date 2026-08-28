# Cloudflare production bootstrap

This runbook deploys ContextGateway against the existing Cloudflare D1 database named `mcp-context`.

## 1. Install dependencies and confirm Cloudflare auth

```bash
npm install
npx wrangler whoami
```

If Wrangler is not authenticated, run:

```bash
npx wrangler login
```

## 2. Resolve the D1 database ID

The production Wrangler binding must use both the database name and the Cloudflare D1 UUID.

```bash
npm run db:info
```

Copy the database UUID for `mcp-context` into `wrangler.jsonc` as `database_id`, replacing:

```text
00000000-0000-0000-0000-000000000000
```

Do not create another D1 database just to obtain an ID.

## 3. Apply the production schema

Review the migration first:

```bash
cat migrations/0001_init.sql
```

Then apply it to the remote `mcp-context` database:

```bash
npm run db:migrate:remote
```

Cloudflare D1 migrations are transactional: a failed migration is rolled back and previously successful migrations remain applied.

Verify the tables:

```bash
npx wrangler d1 execute mcp-context --remote --command "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
```

You should see the ContextGateway application tables plus Cloudflare's D1 migration table.

## 4. Generate production secrets

ContextGateway currently requires two Worker secrets:

- `CONTROL_PLANE_TOKEN` — authenticates the Phase 1 internal control API.
- `UPSTREAM_ENCRYPTION_KEY` — a 32-byte AES-GCM key used to encrypt stored upstream headers.

Generate both values locally with Node.js:

```bash
node -e "const c=require('crypto'); console.log('CONTROL_PLANE_TOKEN='+c.randomBytes(32).toString('base64url')); console.log('UPSTREAM_ENCRYPTION_KEY='+c.randomBytes(32).toString('base64url'));"
```

Store the generated values in a local `.env.production` file:

```text
CONTROL_PLANE_TOKEN=<generated-control-token>
UPSTREAM_ENCRYPTION_KEY=<generated-32-byte-base64url-key>
```

`.env.production` is ignored by Git. Never commit these values.

## 5. Deploy the Worker and secrets together

```bash
npx wrangler deploy --secrets-file .env.production
```

The Wrangler configuration declares both secrets as required, so deployment fails rather than silently launching without them.

Record the deployed `workers.dev` URL printed by Wrangler.

## 6. Smoke test

Replace `<WORKER_URL>` with the URL returned by Wrangler:

```bash
curl -sS <WORKER_URL>/healthz
```

Expected response:

```json
{"status":"ok","service":"contextgateway-edge"}
```

## 7. Create the first production account

Load the control token into your shell without putting it in command history where possible, then call:

```bash
curl -sS <WORKER_URL>/v1/control/accounts \
  -H "Authorization: Bearer $CONTROL_PLANE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"ContextGateway Demo","plan":"free"}'
```

Save the returned account ID. The next step is to register a real HTTPS MCP upstream, issue a scoped agent key, and verify both an allowed and denied MCP operation in the trace log.

## Production safety notes

- Keep `ALLOW_INSECURE_UPSTREAMS` unset in production.
- Do not use Cloudflare edge rate-limit counters as subscription billing meters; they are abuse-control primitives rather than exact usage accounting.
- Do not store MCP request or response bodies in traces by default.
- Rotate `CONTROL_PLANE_TOKEN` after user authentication/RBAC replaces the Phase 1 internal control API.
- Rotating `UPSTREAM_ENCRYPTION_KEY` requires a re-encryption migration for stored upstream headers; do not rotate it ad hoc after production gateways exist.
