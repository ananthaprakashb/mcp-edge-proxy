# Production bootstrap

This runbook takes the Phase 1 ContextGateway edge service from a merged repository to a first live Cloudflare Worker deployment.

## 1. Install dependencies

```bash
npm install
```

Confirm Wrangler is authenticated to the Cloudflare account that owns the D1 database:

```bash
npx wrangler whoami
```

## 2. Verify the existing D1 database

ContextGateway uses the Cloudflare D1 database:

```text
mcp-context
```

The production binding is already configured in `wrangler.jsonc` with database ID:

```text
139c3fd4-bbcb-41b6-868c-0fa6f589ab02
```

You can verify it with:

```bash
npm run db:info
```

## 3. Apply the production schema

Apply the checked-in migrations to the remote database:

```bash
npm run db:migrate:remote
```

Wrangler should report migration `0001_init.sql` as applied. If it is already present, do not manually rerun the SQL.

## 4. Create Worker secrets

ContextGateway requires two Worker secrets.

Generate a long random control-plane bearer token locally. For example:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Store it directly in Cloudflare without committing it:

```bash
npx wrangler secret put CONTROL_PLANE_TOKEN
```

Generate the 32-byte AES-GCM key used to encrypt stored upstream credentials:

```bash
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))"
```

Store it:

```bash
npx wrangler secret put UPSTREAM_ENCRYPTION_KEY
```

Keep a secure backup of the encryption key. Losing it makes already-encrypted upstream credential records unreadable. Never put either value in GitHub, issue comments, logs, or chat.

## 5. Verify and deploy

Run local verification first:

```bash
npm run typecheck
npm test
```

Then deploy:

```bash
npm run deploy
```

Wrangler prints the deployed Worker URL, normally similar to:

```text
https://contextgateway-edge.<account-subdomain>.workers.dev
```

## 6. Health check

```bash
curl -sS https://YOUR-WORKER-URL/healthz
```

Expected response:

```json
{"status":"ok","service":"contextgateway-edge"}
```

## 7. Create the first account

Set the control token only in your local shell:

```bash
export CONTROL_PLANE_TOKEN='the-value-you-put-in-cloudflare'
```

Create a free validation account:

```bash
curl -sS https://YOUR-WORKER-URL/v1/control/accounts \
  -H "Authorization: Bearer $CONTROL_PLANE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"ContextGateway Validation","plan":"free"}'
```

Save the returned account `id`.

## 8. Next validation

Once a reachable MCP test server is available:

1. create a gateway through `POST /v1/control/gateways`;
2. issue a scoped key through `POST /v1/control/keys`;
3. call one allowed MCP tool and confirm the upstream receives it;
4. call one denied tool and confirm ContextGateway rejects it before forwarding;
5. query `/v1/control/traces` and verify both policy decisions are recorded without request or response bodies.

Do not use a production credential-bearing MCP server for the first validation. Start with a non-sensitive test endpoint, then move to a Cloudflare Tunnel/private connection once the policy and trace path is proven.
