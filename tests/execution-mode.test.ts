import { describe, expect, it } from "vitest";
import { evaluateExecutionMode, parseExecutionMode } from "../src/execution-mode";

describe("credential execution mode", () => {
  it("keeps omitted API values backward compatible", () => {
    expect(parseExecutionMode(undefined)).toBe("direct");
  });

  it("rejects invalid execution modes", () => {
    expect(() => parseExecutionMode("capability_optional")).toThrow(/executionMode/);
  });

  it("blocks direct execution for capability-required keys", () => {
    expect(evaluateExecutionMode("capability_required", "agent_key")).toEqual({
      allowed: false,
      reason: "key_requires_capability_exchange",
    });
  });

  it("allows a capability issued from a capability-required key", () => {
    expect(evaluateExecutionMode("capability_required", "capability")).toEqual({
      allowed: true,
      reason: "capability_required_satisfied",
    });
  });

  it("keeps direct keys compatible with both execution paths", () => {
    expect(evaluateExecutionMode("direct", "agent_key").allowed).toBe(true);
    expect(evaluateExecutionMode("direct", "capability").allowed).toBe(true);
  });
});
