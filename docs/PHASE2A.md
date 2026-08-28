# Phase 2A — Authenticated control plane and dashboard

Phase 2A turns the validated ContextGateway edge service into a self-service developer product.

## What ships

- Better Auth 1.7 on the existing Cloudflare Worker and D1 database.
- Email/password sign-up and sign-in with a 12-character minimum password.
- Optional GitHub and Google OAuth; buttons appear only when both credentials for a provider are configured.
- User sessions stored in D1 and served from `/api/auth/*`.
- Workspaces mapped 1:1 to the existing ContextGateway billing/account tenant.
- Workspace roles: `owner`, `admin`, `member`.
- Owner/admin write enforcement for gateways and agent credentials.
- Browser dashboard for gateway creation, scoped key issuance/revocation, metrics, and trace exploration.
- Plaintext agent keys are shown once and remain hash-only in D1.
- Existing `/v1/control/*` bearer-token routes remain the internal/bootstrap/billing control plane and are not used by normal dashboard users.

## Production migration

After merging Phase 2A, apply migration `0002_auth_workspaces.sql` before deploying the Worker:

```bash
npm install
npm run db:migrate:remote
```

The migration adds Better Auth's core `user`, `session`, `account`, and `verification` tables plus ContextGateway `workspaces` and `workspace_members`.

## Required auth secret

Generate a dedicated Better Auth secret. Do not reuse the control-plane token or upstream encryption key.

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
npx wrangler secret put BETTER_AUTH_SECRET
```

## Optional GitHub OAuth

Create a GitHub OAuth application with callback URL:

```text
https://contextgateway-edge.subhafash-86.workers.dev/api/auth/callback/github
```

Then store:

```bash
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
```

## Optional Google OAuth

Create a Google OAuth web client with redirect URI:

```text
https://contextgateway-edge.subhafash-86.workers.dev/api/auth/callback/google
```

Then store:

```bash
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
```

Social sign-in is optional for the first deployment; email/password works with only `BETTER_AUTH_SECRET` configured.

## Deploy

```bash
npm run typecheck
npm test
npm run build
npm run deploy
```

The same Worker deployment serves the React SPA as static assets and handles `/api/*`, `/v1/*`, and `/healthz` through Worker code.

## First validation

1. Open the Worker URL in a browser.
2. Create an email/password account.
3. Create a workspace.
4. Add a non-sensitive MCP gateway.
5. Issue a key scoped to one method/tool.
6. Copy the key from the one-time display.
7. Make an allowed and denied MCP request.
8. Confirm both appear in Trace Explorer.
9. Revoke the key and confirm a later request returns `401`.

## Security boundary

Phase 2A is a usable MVP, not the final public-GA auth posture. Before broad public launch add email verification/reset delivery, login abuse controls, stronger audit durability, security headers/CSP review, invitation flows, and explicit session/device management.
