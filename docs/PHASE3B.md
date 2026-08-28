# Phase 3B — capability-required keys and explainable policy

Phase 3B turns the Phase 3 capability exchange into an enforceable key mode and makes authorization decisions explainable without retaining MCP request bodies, prompts, tool arguments, capability tokens, or upstream responses.

## Key execution modes

Every agent key has one execution mode:

- `direct` — backward-compatible. The `cg_live_*` key may invoke the MCP gateway directly and may also mint `cg_cap_*` capabilities.
- `capability_required` — recommended. The `cg_live_*` key may mint capabilities but direct MCP invocation with that reusable key is rejected with `403 capability_required`.

Existing keys migrate to `direct`. The API also defaults omitted `executionMode` to `direct` for compatibility. The dashboard defaults newly issued keys to `capability_required`.

## Recommended trust boundary

```text
Trusted orchestrator
  keeps cg_live_*
       |
       | POST /v1/mcp/:gatewayId/capabilities
       v
ContextGateway
  returns short-lived cg_cap_*
       |
       v
Agent / tool executor
  receives cg_cap_* only
       |
       | POST /v1/mcp/:gatewayId
       v
ContextGateway
  verifies scope + optional argument digest
  re-checks parent key and current policy
  consumes JTI atomically in D1
  injects upstream credentials
       |
       v
MCP server
```

## Explainable traces

Trace rows now include metadata-only authorization context:

- `auth_mode`: `agent_key` or `capability`
- `capability_jti`: the non-secret unique identifier from a verified capability; the token itself is never retained
- `policy_reason`: a stable explanation such as `key_requires_capability_exchange`, `policy:name_not_allowed`, or the successful mode/policy/capability combination
- `policy_method_rule`: the exact method rule that matched, including `*` when applicable
- `policy_name_rule`: the exact name rule that matched, including `*` when applicable

Trace Explorer exposes these fields and supports auth-mode filtering and searches across reason/JTI metadata.

## Migration

After merging:

```bash
npm install
npm run db:migrate:remote
```

Confirm `0005_execution_policy_explain.sql` is applied.

Then deploy:

```bash
npm run deploy
```

No new Cloudflare secret is required by Phase 3B. Continue using the Phase 3 `CAPABILITY_SIGNING_KEY`.

## Dashboard validation

1. Open **Gateways & keys**.
2. View an existing active key.
3. Change its execution mode to **Capability required**.
4. Confirm the badge changes to `Capability required`.
5. Open **Trace explorer** after the smoke test below.

Existing keys begin as `Direct compatible` after migration. Changing the mode does not rotate the plaintext key.

## Production smoke

Use a test gateway whose upstream accepts the MCP smoke request, such as the existing validation gateway pointing to `https://httpbin.org/anything`.

The selected agent key must:

- be active;
- allow `tools/call` and the selected tool name;
- be set to `capability_required` in the dashboard.

PowerShell:

```powershell
$env:CONTEXTGATEWAY_BASE_URL = "https://contextgateway-edge.subhafash-86.workers.dev"
$env:GATEWAY_ID = "YOUR_GATEWAY_ID"
$env:AGENT_KEY = "YOUR_CG_LIVE_KEY"
$env:MCP_METHOD = "tools/call"
$env:MCP_NAME = "demo.allowed"

npm run smoke:capability-required
```

Expected output:

```text
✓ direct cg_live_* execution blocked: HTTP 403 capability_required
✓ the same cg_live_* key can still mint a short-lived capability
✓ cg_cap_* execution allowed: HTTP 200
✓ response confirms capability + capability_required enforcement
✓ capability remains single-use: HTTP 401 capability_replayed

PASS: capability-required keys cannot bypass the exchange, while minted single-use capabilities execute normally.
```

## Trace Explorer validation

After the smoke test, the explorer should include approximately:

```text
capability_required  agent_key   key_requires_capability_exchange
allowed              capability  mode:capability_required_satisfied;policy:allowed_exact;capability:scope_and_arguments_bound
capability_replayed  capability  capability_single_use_already_consumed
```

The allowed row should also show the matching method/tool policy rules and a truncated capability JTI in the UI.

## Security properties

- A `capability_required` key cannot invoke the MCP execution endpoint directly.
- That same reusable key can still mint a capability within its current method/name policy.
- Capability execution re-checks the parent key, subscription, and current policy.
- Parent-key revocation invalidates outstanding capabilities.
- Capability replay remains atomically enforced through D1.
- Direct-bypass denial occurs before rate/quota accounting and upstream forwarding.
- Explainability stores authorization metadata only; no prompt, request body, tool arguments, capability token, upstream credential, or response body is added to trace storage.
