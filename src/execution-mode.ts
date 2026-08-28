import type { ExecutionMode } from "./types";

export type AuthMode = "agent_key" | "capability";

export function parseExecutionMode(value: unknown, fallback: ExecutionMode = "direct"): ExecutionMode {
  if (value === undefined || value === null || value === "") return fallback;
  if (value === "direct" || value === "capability_required") return value;
  throw new Error("executionMode must be direct or capability_required");
}

export function evaluateExecutionMode(
  executionMode: ExecutionMode,
  authMode: AuthMode,
): { allowed: boolean; reason: string } {
  if (executionMode === "capability_required" && authMode === "agent_key") {
    return { allowed: false, reason: "key_requires_capability_exchange" };
  }
  if (executionMode === "capability_required") {
    return { allowed: true, reason: "capability_required_satisfied" };
  }
  return { allowed: true, reason: authMode === "capability" ? "direct_key_used_via_capability" : "direct_key_execution_allowed" };
}
