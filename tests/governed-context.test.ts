import { describe, expect, it } from "vitest";
import { capabilityArgumentsMatch, issueCapabilityToken } from "../src/capability";
import {
  normalizeAllowedPaths,
  normalizeDocumentKey,
  parseContextDocument,
  pathAllowed,
  readJsonPointer,
} from "../src/context-document";

describe("governed context normalization", () => {
  it("normalizes JSON and YAML to equivalent structured values", async () => {
    const json = await parseContextDocument("json", '{"public":{"message":"hello"},"count":2}');
    const yaml = await parseContextDocument("yaml", "public:\n  message: hello\ncount: 2\n");
    expect(json.normalized).toEqual(yaml.normalized);
    expect(json.topLevelKeys).toEqual(["count", "public"]);
    expect(json.contentHash).not.toBe(yaml.contentHash); // provenance hashes bind the exact source bytes
  });

  it("turns markdown headings into addressable sections", async () => {
    const parsed = await parseContextDocument("markdown", "Intro text\n\n# Benefits\nHealth plan\n\n## PTO\n20 days");
    expect(readJsonPointer(parsed.normalized, "/intro")).toBe("Intro text");
    expect(readJsonPointer(parsed.normalized, "/sections/benefits/text")).toBe("Health plan");
    expect(readJsonPointer(parsed.normalized, "/sections/pto/text")).toBe("20 days");
  });

  it("wraps plain text behind the /text path", async () => {
    const parsed = await parseContextDocument("text", "hello world");
    expect(readJsonPointer(parsed.normalized, "/text")).toBe("hello world");
  });

  it("accepts JSON or YAML shaped OKF-style objects", async () => {
    const parsed = await parseContextDocument("okf", "version: '1'\nnodes:\n  - id: fact-1\n    value: active\n");
    expect(readJsonPointer(parsed.normalized, "/nodes/0/id")).toBe("fact-1");
  });
});

describe("document path policy", () => {
  it("supports exact and subtree grants but fails closed for a missing path", () => {
    expect(pathAllowed(["/public/*"], "/public/message")).toBe(true);
    expect(pathAllowed(["/public/*"], "/public")).toBe(true);
    expect(pathAllowed(["/public/*"], "/private/secret")).toBe(false);
    expect(pathAllowed(["/public/*"], null)).toBe(false);
    expect(pathAllowed(["*"], null)).toBe(true);
  });

  it("normalizes and rejects malformed policy paths", () => {
    expect(normalizeAllowedPaths(["/public/*", "/public/*", "/name"])).toEqual(["/public/*", "/name"]);
    expect(() => normalizeAllowedPaths(["private"])).toThrow();
  });

  it("uses workspace-safe document keys", () => {
    expect(normalizeDocumentKey("employee-handbook.v2")).toBe("employee-handbook.v2");
    expect(() => normalizeDocumentKey("../other-workspace")).toThrow();
    expect(() => normalizeDocumentKey("Has Spaces")).toThrow();
  });
});

describe("capability-bound context reads", () => {
  it("binds documentKey and path so the same capability cannot read a different field", async () => {
    const signingKey = "phase10-test-signing-key-that-is-at-least-32-characters";
    const argumentsValue = { documentKey: "employee-handbook", path: "/public/benefits" };
    const issued = await issueCapabilityToken(signingKey, {
      accountId: "account-1",
      gatewayId: "gateway-1",
      apiKeyId: "key-1",
      method: "tools/call",
      name: "contextgateway.document.read",
      arguments: argumentsValue,
      bindArguments: true,
    });
    expect(issued.claims.argumentsSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(await capabilityArgumentsMatch(issued.claims, argumentsValue)).toBe(true);
    expect(await capabilityArgumentsMatch(issued.claims, { documentKey: "employee-handbook", path: "/private/payroll" })).toBe(false);
    expect(await capabilityArgumentsMatch(issued.claims, { documentKey: "another-document", path: "/public/benefits" })).toBe(false);
  });
});
