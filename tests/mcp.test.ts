import { describe, expect, it } from "vitest";
import { extractMcpOperation } from "../src/mcp";

function request(headers: Record<string, string>, body: unknown): Request {
  return new Request("https://example.test/v1/mcp/gw", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("MCP operation extraction", () => {
  it("extracts method, name, and arguments from JSON-RPC", async () => {
    const operation = await extractMcpOperation(request({}, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "demo.allowed", arguments: { value: 42 } },
    }));
    expect(operation).toMatchObject({
      method: "tools/call",
      name: "demo.allowed",
      arguments: { value: 42 },
      hasArguments: true,
      consistent: true,
    });
  });

  it("accepts matching MCP headers and JSON-RPC body", async () => {
    const operation = await extractMcpOperation(request({
      "Mcp-Method": "tools/call",
      "Mcp-Name": "demo.allowed",
    }, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "demo.allowed", arguments: {} },
    }));
    expect(operation.consistent).toBe(true);
  });

  it("detects a method or name mismatch between headers and body", async () => {
    const methodMismatch = await extractMcpOperation(request({ "Mcp-Method": "tools/list" }, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "demo.allowed" },
    }));
    expect(methodMismatch.consistent).toBe(false);

    const nameMismatch = await extractMcpOperation(request({
      "Mcp-Method": "tools/call",
      "Mcp-Name": "demo.safe",
    }, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "demo.dangerous" },
    }));
    expect(nameMismatch.consistent).toBe(false);
  });

  it("rejects a JSON-RPC batch even when a single MCP header is supplied", async () => {
    const operation = await extractMcpOperation(request({
      "Mcp-Method": "tools/call",
      "Mcp-Name": "demo.allowed",
    }, [
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "demo.allowed" } },
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "demo.other" } },
    ]));
    expect(operation.consistent).toBe(false);
  });

  it("rejects malformed application/json instead of trusting the headers", async () => {
    const malformed = new Request("https://example.test/v1/mcp/gw", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "Mcp-Method": "tools/call",
        "Mcp-Name": "demo.allowed",
      },
      body: "{not-json",
    });
    const operation = await extractMcpOperation(malformed);
    expect(operation.consistent).toBe(false);
  });
});
