# ContextGateway custom domain

Production hostname:

```text
https://contextgateway.sharecapsule.org
```

ContextGateway is deployed as a Cloudflare Worker Custom Domain. The Worker is the origin, so Cloudflare creates the DNS record and manages TLS automatically when `wrangler deploy` applies the route.

## Wrangler configuration

```json
"routes": [
  {
    "pattern": "contextgateway.sharecapsule.org",
    "custom_domain": true
  }
],
"vars": {
  "BETTER_AUTH_URL": "https://contextgateway.sharecapsule.org"
}
```

The existing `workers.dev` endpoint remains enabled as a fallback, but production authentication is canonicalized to the custom hostname.

## Deploy

```powershell
git checkout main
git pull
npm install
npm run typecheck
npm test
npm run build
npm run deploy
```

No D1 migration or new Worker secret is required.

## Cloudflare prerequisite

`sharecapsule.org` must be an active Cloudflare zone in the same account that owns the Worker. The hostname `contextgateway.sharecapsule.org` must not already have an existing CNAME record, because Cloudflare Custom Domains create and manage their own DNS record and certificate.

After deployment, check Worker > Settings > Domains & Routes and confirm `contextgateway.sharecapsule.org` appears as a Custom Domain.

## OAuth callbacks

Better Auth uses `/api/auth/callback/<provider>` under the canonical base URL. If social providers are enabled, configure the production callback URLs as:

```text
GitHub: https://contextgateway.sharecapsule.org/api/auth/callback/github
Google: https://contextgateway.sharecapsule.org/api/auth/callback/google
```

GitHub OAuth Apps generally use a single production callback URL, so replace the prior workers.dev callback with the custom-domain URL. Google OAuth clients can list the custom-domain redirect URI alongside local development redirects.

## Validation

```powershell
curl.exe -I https://contextgateway.sharecapsule.org/
curl.exe https://contextgateway.sharecapsule.org/healthz
```

Then validate:

1. Email/password sign-in.
2. GitHub/Google sign-in if configured.
3. Dashboard navigation.
4. Existing public gateway health test.
5. Capability regression:

```powershell
$env:CONTEXTGATEWAY_BASE_URL = "https://contextgateway.sharecapsule.org"
npm run smoke:capability-required
npm run smoke:context
```

After the custom hostname is validated, use it in public launch posts and marketplace listings rather than the workers.dev hostname.
