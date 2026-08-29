# Password recovery

ContextGateway uses Better Auth's email/password reset flow and Resend for transactional delivery.

## Production flow

1. An unauthenticated user opens `/forgot-password`.
2. The client calls Better Auth `requestPasswordReset` with the canonical redirect `https://contextgateway.sharecapsule.org/reset-password`.
3. If the account exists, Better Auth creates a short-lived reset token and calls the configured reset-email hook.
4. The Worker sends the link through Resend without logging the link/token.
5. The user lands on `/reset-password?token=...` and chooses a new password.
6. Better Auth resets the credential and revokes the user's existing sessions.

The reset token is valid for 30 minutes. The forgot-password UI deliberately uses the same success wording whether or not an account exists.

## Resend setup

Verify `sharecapsule.org` in Resend before using a `@sharecapsule.org` sender. Follow Resend's DNS verification instructions for the domain.

Set the Worker secrets locally from the repository root:

```powershell
npx wrangler secret put RESEND_API_KEY
npx wrangler secret put AUTH_EMAIL_FROM
```

Suggested sender value:

```text
ContextGateway <security@sharecapsule.org>
```

`AUTH_EMAIL_FROM` is stored as a Worker secret for deployment simplicity even though the sender identity itself is not sensitive.

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
2. Select **Forgot password?**.
3. Enter an existing email address.
4. Confirm the UI says only that an email may have been sent; it must not disclose account existence.
5. Open the received email and follow the reset link.
6. Enter a new password of at least 12 characters and confirm it.
7. Sign in with the new password.
8. Verify an older logged-in browser/session has been invalidated.
9. Repeat the forgot-password request with a nonexistent email and verify the public response is indistinguishable.
10. Confirm Worker logs do not contain the reset token/link or the new password.

If mail is not delivered, verify the Resend domain status, API key, sender identity, and Worker logs. Delivery failures are logged only as a generic error and intentionally omit recipient/token details.
