import { describe, expect, it } from "vitest";
import { evaluatePolicy, evaluatePolicyDetailed, normalizePolicyInput, parsePolicy } from "../src/policy";

describe("MCP policy evaluation", () => {
  it("allows exact MCP method and tool matches", () => {
    const policy = parsePolicy('["tools/call"]', '["github.create_issue"]');
    expect(evaluatePolicy(policy, "tools/call", "github.create_issue")).toBe(true);
    expect(evaluatePolicy(policy, "tools/call", "github.delete_repo")).toBe(false);
    expect(evaluatePolicyDetailed(policy, "tools/call", "github.create_issue")).toEqual({
      allowed: true,
      reason: "allowed_exact",
      methodRule: "tools/call",
      nameRule: "github.create_issue",
    });
  });

  it("reports the exact failing policy dimension", () => {
    const policy = parsePolicy('["tools/call"]', '["github.create_issue"]');
    expect(evaluatePolicyDetailed(policy, "resources/read", "github.create_issue")).toMatchObject({
      allowed: false,
      reason: "method_not_allowed",
      methodRule: null,
    });
    expect(evaluatePolicyDetailed(policy, "tools/call", "github.delete_repo")).toEqual({
      allowed: false,
      reason: "name_not_allowed",
      methodRule: "tools/call",
      nameRule: null,
    });
  });

  it("explains standalone wildcard matches", () => {
    const policy = parsePolicy('["tools/list","tools/call"]', '["*"]');
    expect(evaluatePolicy(policy, "tools/list", null)).toBe(true);
    expect(evaluatePolicy(policy, "tools/call", "anything")).toBe(true);
    expect(evaluatePolicyDetailed(policy, "tools/call", "anything")).toEqual({
      allowed: true,
      reason: "allowed_wildcard",
      methodRule: "tools/call",
      nameRule: "*",
    });
  });

  it("fails closed when the MCP method is absent", () => {
    const policy = parsePolicy('["*"]', '["*"]');
    expect(evaluatePolicy(policy, null, null)).toBe(false);
    expect(evaluatePolicyDetailed(policy, null, null).reason).toBe("missing_method");
  });

  it("rejects partial glob rules", () => {
    expect(() => normalizePolicyInput(["github.*"])).toThrow(/standalone/);
  });
});
