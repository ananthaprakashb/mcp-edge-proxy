# Phase 5 — Workspace collaboration

Phase 5 turns ContextGateway workspaces into collaborative tenants while keeping the existing account, billing, gateway, policy, and trace model intact.

## Roles

| Capability | Owner | Admin | Member |
| --- | --- | --- | --- |
| View gateways, traces, billing usage, and team roster | Yes | Yes | Yes |
| Create gateways and agent keys | Yes | Yes | No |
| Invite members | Yes | Yes | No |
| Invite admins | Yes | No | No |
| Revoke member invites | Yes | Yes | No |
| Revoke admin invites | Yes | No | No |
| Change member/admin roles | Yes | No | No |
| Remove admins | Yes | No | No |
| Remove members | Yes | Yes | No |
| Manage Stripe billing | Yes | No | No |

Owner transfer is intentionally not included in this phase.

## Plan seat limits

The existing plan entitlements are now enforced for workspace membership:

- Free: 1 member
- Pro: 3 members
- Team: 15 members

Pending invitations reserve seats. For example, a Pro workspace with one owner and two pending invitations has no additional seats available.

The API checks limits before invitation creation and acceptance. D1 also has a `BEFORE INSERT` trigger on `workspace_members`, which is the final race-safe guardrail that prevents the actual member count from exceeding the current plan.

If a paid workspace later downgrades below its existing member count, existing membership is not destructively removed. New invite acceptance is blocked until the workspace is back within its plan limit.

## Invitation security

- Invitations expire after 7 days.
- An invitation is bound to the invited email address.
- The invite token is generated from 32 random bytes.
- D1 stores only the SHA-256 hash of the token.
- The plaintext invite link is returned only when the invitation is created.
- Pending invitations can be revoked immediately.
- Invite preview and acceptance submit the token in the POST body instead of placing it in an API path.
- The browser invitation link uses a URL fragment (`#invite=...`) so the token is not sent to the server when the landing page is requested.

ContextGateway does not send invitation email in Phase 5. The owner/admin copies the one-time invitation link and sends it using their normal trusted communication channel. Email delivery can be added later without changing the invite data model.

## API

### Team roster

```text
GET /v1/app/workspaces/:workspaceId/members
```

Returns:

- workspace role and plan
- members
- pending invites for owner/admin
- seat usage (`used`, `reserved`, `limit`, `available`)

### Create invitation

```text
POST /v1/app/workspaces/:workspaceId/invites
Content-Type: application/json

{
  "email": "teammate@example.com",
  "role": "member"
}
```

`role` may be `member` or `admin`. Admin actors may create `member` invitations only.

The successful response contains `invitation.inviteUrl`. Copy it immediately; the plaintext token cannot be recovered later.

### Revoke invitation

```text
DELETE /v1/app/workspaces/:workspaceId/invites/:inviteId
```

### Preview invitation

```text
POST /v1/app/invitations/preview
Content-Type: application/json

{
  "token": "cginv_..."
}
```

The signed-in account email must match the invitation email.

### Accept invitation

```text
POST /v1/app/invitations/accept
Content-Type: application/json

{
  "token": "cginv_..."
}
```

### Change member role

```text
PATCH /v1/app/workspaces/:workspaceId/members/:userId
Content-Type: application/json

{
  "role": "admin"
}
```

Owner only. Owner transfer is rejected.

### Remove member

```text
DELETE /v1/app/workspaces/:workspaceId/members/:userId
```

Owners may remove admins or members. Admins may remove members only. Self-removal and owner removal are rejected.

## Dashboard validation

After deployment:

1. Open the new **Team** tab.
2. Free plan should show `1` member, `0` available seats, and block invitations.
3. Upgrade/use a Pro workspace and confirm the seat limit is `3`.
4. Create a member invitation and copy the generated link.
5. Confirm the pending invite reserves one seat.
6. Open the link in another browser/private profile.
7. Create/sign in with the exact invited email address.
8. Confirm ContextGateway shows the invitation preview before joining.
9. Accept the invitation.
10. Confirm the new user sees the workspace in the workspace switcher.
11. As owner, promote the member to admin and back to member.
12. Confirm an admin can invite/remove members but cannot invite admins or change roles.
13. Revoke a pending invite and confirm its link no longer works.

## Deployment

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
0007_workspace_collaboration.sql
```

No new Worker secret is required.
