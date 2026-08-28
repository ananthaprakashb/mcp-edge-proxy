import { describe, expect, it } from "vitest";
import { evaluatePolicy, normalizePolicyInput, parsePolicy } from "../src/policy";

describe("MCP policy evaluation", () => {
  it("allows exact MCP method and tool matches", () => {
    const policy = parsePolicy('["tools/call"]', '["github.create_issue"]');
    expect(evaluatePolicy(policy, "tools/call", "github.create_issue")).toBe(true);
    expect(evaluatePolicy(policy, "tools/call", "github.delete_repo")).toBe(false);
  });

  it("supports the standalone wildcard", () => {
    const policy = parsePolicy('["tools/list","tools/call"]', '["*"]');
    expect(evaluatePolicy(policy, "tools/list", null)).toBe(true);
    expect(evaluatePolicy(policy, "tools/call", "anything")).toBe(true);
  });

  it("fails closed when the MCP method is absent", () => {
    const policy = parsePolicy('["*"]', '["*"]');
    expect(evaluatePolicy(policy, null, null)).toBe(false);
  });

  it("rejects partial glob rules", () => {
    expect(() => normalizePolicyInput(["github.*"])).toThrow(/standalone/);
  });
});
