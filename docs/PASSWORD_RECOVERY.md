# Password recovery

ContextGateway uses Better Auth's email/password reset flow and Resend for transactional delivery.

## Production flow

1. An unauthenticated user selects **Forgot password?** directly below the password field.
2. `/forgot-password` first checks `GET /v1/app/password-recovery/status` so a missing email configuration is visible instead of silently pretending mail was sent.
3. The form posts the email address to `POST /v1/app/password-recovery/request`.
4. The Worker verifies transactional email is configured, then calls Better Auth `requestPasswordReset` with the canonical redirect `https://contextgateway.sharecapsule.org/reset-password`.
5. If the account exists, Better Auth creates a short-lived reset token and invokes the reset-email hook.
6. The Worker queues Resend delivery with the request `ExecutionContext.waitUntil()` and never logs the reset URL/token or recipient.
7. The user lands on `/reset-password?token=...` and chooses a new password.
8. Better Auth resets the credential and revokes the user's existing sessions.

The reset token is valid for 30 minutes. Once transactional email is configured, the forgot-password UI deliberately uses the same success wording whether or not an account exists.

## Transactional email setup — Resend + Cloudflare

Use a dedicated sending subdomain so authentication mail is isolated from other ShareCapsule mail:

```text
auth.sharecapsule.org
```

### 1. Add the sending domain in Resend

In Resend:

1. Open **Domains**.
2. Choose **Add domain**.
3. Enter `auth.sharecapsule.org`.
4. Resend will display DNS records for SPF/DKIM (and related return-path records).

### 2. Add the Resend DNS records in Cloudflare

Open **Cloudflare → sharecapsule.org → DNS → Records** and copy the exact records shown by Resend.

Cloudflare's **Name** field is normally relative to `sharecapsule.org`. For example, if Resend shows `send.auth.sharecapsule.org`, Cloudflare normally expects `send.auth` in the Name field. Always use the exact values Resend provides for your account.

Return to Resend and wait until `auth.sharecapsule.org` shows **Verified**.

### 3. Create a sending-only Resend API key

In Resend:

1. Open **API Keys**.
2. Create `ContextGateway Production`.
3. Prefer **Sending access** restricted to `auth.sharecapsule.org` rather than Full Access.
4. Copy the generated `re_...` key once. Do not commit or paste it into chat/issues.

### 4. Store the Resend key in the production Worker

From the repository root:

```powershell
npx wrangler secret put RESEND_API_KEY
```

Paste the `re_...` value when Wrangler prompts.

Then set the sender identity:

```powershell
npx wrangler secret put AUTH_EMAIL_FROM
```

Use:

```text
ContextGateway <security@auth.sharecapsule.org>
```

`AUTH_EMAIL_FROM` is stored as a Worker secret for deployment simplicity even though the sender identity itself is not sensitive.

### 5. Verify the Worker sees the configuration

After deployment, open:

```text
https://contextgateway.sharecapsule.org/v1/app/password-recovery/status
```

Expected:

```json
{"configured":true}
```

If it returns `{"configured":false}`, at least one of `RESEND_API_KEY` or `AUTH_EMAIL_FROM` is missing from the deployed Worker environment.

Do not commit the Resend API key or a reset URL/token to the repository.

## Deploy

No D1 migration is required.

```powershell
git checkout main
git pull
npm install
npm run typecheck
npm test
npm run build
npm run deploy
```

## Production validation

1. Open `https://contextgateway.sharecapsule.org` and sign out.
2. Confirm **Forgot password?** appears directly below the password field and above **Sign in**; it must not appear on **Create account**.
3. Select **Forgot password?** and confirm `/forgot-password` opens.
4. Confirm `/v1/app/password-recovery/status` reports `configured: true`.
5. Enter an existing email address and select **Send reset link**.
6. Confirm the UI says only that an email may have been sent; it must not disclose account existence.
7. In Resend, open **Emails / Logs** and confirm the message shows as sent/delivered.
8. Open the received email and follow the reset link.
9. Enter a new password of at least 12 characters and confirm it.
10. Sign in with the new password and verify the old password fails.
11. Verify an older logged-in browser/session has been invalidated.
12. Repeat the request with a nonexistent email and verify the public response remains generic.
13. Confirm Worker logs do not contain the reset token/link, recipient, or new password.

## Troubleshooting no-email cases

Check these in order:

1. `GET /v1/app/password-recovery/status` must return `{"configured":true}`.
2. Resend → Domains → `auth.sharecapsule.org` must show **Verified**.
3. Resend → API Keys must contain the sending key used by the Worker.
4. Resend → Emails / Logs should show the reset attempt. If no attempt appears, inspect Cloudflare Worker logs for the generic password-recovery delivery error.
5. `AUTH_EMAIL_FROM` must use a sender on the verified domain, for example `ContextGateway <security@auth.sharecapsule.org>`.
6. Re-run `npx wrangler secret put ...` against the same Cloudflare account/environment used by `npm run deploy` if the status endpoint reports false.
