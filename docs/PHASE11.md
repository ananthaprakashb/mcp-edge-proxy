# Phase 11 — Product UX and onboarding redesign

Phase 11 consolidates the functionality delivered in Phases 1–10 into a clearer SaaS information architecture without changing the existing backend contracts.

## Goals

- Reduce the amount of functionality buried in the Team page.
- Make the product understandable to a first-time user without a runbook.
- Preserve every security and operational feature already implemented.
- Improve navigation, hierarchy, empty states, mobile behavior, and common workflows.
- Keep this phase client-only: no D1 migration, Worker secret, or plan upgrade is required.

## New navigation

The sidebar is split into two groups.

### Protect

1. **Overview** — posture, onboarding, recent policy decisions
2. **Gateways** — MCP upstreams and agent credentials
3. **Governed context** — documents, versions, policies, access history
4. **Trace explorer** — request decisions and policy explanations

### Operate

5. **Operations** — gateway health, secret lifecycle, security audit, retention
6. **Team** — members, invitations, roles
7. **Billing & usage** — quota, plan, Stripe controls

This removes the previous pattern where Context, Health, Secret Lifecycle, Audit, Retention, and Team were stacked on one very long Team page.

## New application shell

`client/AppV2.tsx` is the Phase 11 shell. The legacy `client/App.tsx` remains in the repository during validation as a rollback/reference implementation, but `client/main.tsx` now renders `AppV2`.

The redesigned shell adds:

- grouped sidebar navigation
- workspace + plan + role context in the sidebar
- mobile navigation drawer
- sticky page header and breadcrumb
- clearer product status indicators
- consistent privacy-safe telemetry labeling
- responsive page grids and cards

## Overview onboarding

The Overview page automatically tracks four foundation steps using existing workspace data:

1. Connect an MCP gateway
2. Issue an agent key
3. Run protected MCP traffic
4. Add governed context

There is no separate onboarding state table. Completion is derived from real resources/activity, so it cannot drift from the product state.

## Gateway experience

The new gateway view includes:

- endpoint and upstream separation
- connection-mode badges
- persisted health status indicator
- active-key count
- last health-check time
- key management inline with the gateway
- capability-required / direct-compatible mode control
- clearer first-gateway empty state

All creation, key issuance, revocation, and execution-mode APIs remain unchanged.

## Context and operations separation

`TeamPanel` now contains collaboration only.

A new `OperationsPanel` owns:

- Gateway Health & Diagnostics
- Credential Lifecycle
- Security Audit Events
- Audit Retention & Integrity

`ContextPanel` is now a top-level Governed Context page.

The underlying Phase 6–10 components and APIs are reused rather than rewritten.

## Authentication and first workspace

Sign-in / sign-up and first-workspace creation have been visually redesigned with clearer security positioning and privacy messaging. Better Auth flows and invitation fragment handling remain unchanged.

## Responsive behavior

At desktop widths the product uses a fixed left navigation rail. Below 900 px it becomes an off-canvas drawer. Dashboard metrics, gateway cards, filters, plan cards, modals, and forms progressively collapse for tablet/mobile layouts.

## Deployment

After merge:

```powershell
git checkout main
git pull
npm install
npm run typecheck
npm test
npm run build
npm run deploy
```

There is no D1 migration in Phase 11.

## Production validation

### 1. Authentication

- sign out
- verify redesigned login screen loads
- sign in using the existing account
- if social auth is enabled, verify its callback still returns to ContextGateway

### 2. Navigation

Verify all seven destinations load without a full browser reload:

- Overview
- Gateways
- Governed context
- Trace explorer
- Operations
- Team
- Billing & usage

Change workspaces, if more than one exists, and verify each page refreshes its workspace-scoped data.

### 3. Overview

Verify:

- metrics load
- gateway health summary is visible
- governed-document count is visible
- onboarding completion reflects the real workspace
- Recent Policy Decisions loads
- onboarding / quick-action buttons navigate to the expected page

### 4. Gateway regression

On the Gateways page:

- existing gateways appear
- Manage keys loads current keys
- existing execution modes are correct
- issue a temporary capability-required key
- copy the one-time secret
- revoke the temporary key

If convenient, create/delete only disposable resources. Phase 11 does not introduce gateway deletion.

### 5. Existing MCP regressions

```powershell
npm run smoke:capability-required
npm run smoke:context
```

Both should still PASS.

### 6. Governed Context

Verify the Phase 10 synthetic document and its policy/access history are still present and can be managed from the new top-level page.

### 7. Operations

Verify:

- Gateway health panel loads and Test connection still works
- Credential lifecycle loads
- Security audit events load
- Audit integrity remains Verified
- retention controls remain available to owner/admin

### 8. Team

Verify Team now contains only collaboration concerns:

- seat metrics
- members
- pending invitations
- role controls

Context/health/security panels should no longer be duplicated underneath Team.

### 9. Billing

Verify current plan, monthly quota, resource counts, and Stripe controls still load.

### 10. Responsive sanity check

Shrink the browser below 900 px:

- sidebar becomes a menu drawer
- drawer opens/closes
- page remains horizontally usable
- filters/forms stack
- gateway cards become single-column
- modals fit within the viewport

## Rollback

The legacy `client/App.tsx` is intentionally retained during Phase 11. If a client-only regression requires an emergency rollback before a fix, `client/main.tsx` can temporarily render `App` again without reverting any backend/data migrations.

Once the redesigned client is validated in production, a later cleanup PR can remove the legacy shell.
