import { afterEach, describe, expect, it, vi } from "vitest";
import { runGatewayHealthCheck, type GatewayHealthTarget } from "../src/gateway-health";
import type { D1Database, D1PreparedStatement, Env } from "../src/types";

class FakeStatement implements D1PreparedStatement {
  bind(..._values: unknown[]): D1PreparedStatement { return this; }
  async first<T = Record<string, unknown>>(): Promise<T | null> { return null; }
  async all<T = Record<string, unknown>>() { return { success: true, results: [] as T[] }; }
  async run<T = unknown>() { return { success: true } as { success: boolean; results?: T[] }; }
}

class FakeDb implements D1Database {
  prepare(_query: string): D1PreparedStatement { return new FakeStatement(); }
  async batch<T = unknown>(_statements: D1PreparedStatement[]) { return [{ success: true }] as Array<{ success: boolean; results?: T[] }>; }
}

function env(): Env {
  return {
    DB: new FakeDb(),
    FREE_RATE_LIMITER: { limit: async () => ({ success: true }) },
    PAID_RATE_LIMITER: { limit: async () => ({ success: true }) },
    CONTROL_PLANE_TOKEN: "control",
    UPSTREAM_ENCRYPTION_KEY: "unused",
    BETTER_AUTH_SECRET: "unused",
    CAPABILITY_SIGNING_KEY: "unused",
  };
}

function gateway(status: GatewayHealthTarget["health_status"]): GatewayHealthTarget {
  return {
    id: "gateway-1",
    account_id: "account-1",
    upstream_url: "https://mcp.example.com/rpc",
    upstream_headers_ciphertext: null,
    upstream_headers_iv: null,
    upstream_secret_version: 1,
    connection_mode: "public",
    health_status: status,
  };
}

function dnsResponse(type: string): Response {
  return new Response(JSON.stringify({
    Status: 0,
    Answer: type === "A" ? [{ type: 1, data: "1.1.1.1" }] : [],
  }), {
    status: 200,
    headers: { "content-type": "application/dns-json" },
  });
}

function mockProbe(upstream: () => Promise<Response>): ReturnType<typeof vi.fn> {
  const mock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
    if (url.hostname === "cloudflare-dns.com") return dnsResponse(url.searchParams.get("type") ?? "A");
    expect(init?.method).toBe("HEAD");
    expect(init?.body).toBeUndefined();
    expect(init?.redirect).toBe("manual");
    return upstream();
  });
  vi.stubGlobal("fetch", mock);
  return mock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("gateway health probes", () => {
  it("uses a side-effect-free HEAD probe and marks a reachable upstream healthy", async () => {
    mockProbe(async () => new Response(null, { status: 204 }));
    const result = await runGatewayHealthCheck(env(), gateway("healthy"), { triggerType: "manual" });
    expect(result).toMatchObject({
      status: "healthy",
      reason: "reachable",
      httpStatus: 204,
      dnsAddresses: ["1.1.1.1"],
    });
  });

  it("classifies upstream authentication rejection without exposing credentials", async () => {
    mockProbe(async () => new Response(null, { status: 401 }));
    const result = await runGatewayHealthCheck(env(), gateway("auth_failure"), { triggerType: "manual" });
    expect(result).toMatchObject({ status: "auth_failure", reason: "upstream_auth_rejected", httpStatus: 401 });
  });

  it("classifies upstream 5xx responses as degraded", async () => {
    mockProbe(async () => new Response(null, { status: 503 }));
    const result = await runGatewayHealthCheck(env(), gateway("degraded"), { triggerType: "manual" });
    expect(result).toMatchObject({ status: "degraded", reason: "upstream_server_error", httpStatus: 503 });
  });

  it("classifies aborted probes as timeouts", async () => {
    mockProbe(async () => { throw new DOMException("Aborted", "AbortError"); });
    const result = await runGatewayHealthCheck(env(), gateway("timeout"), { triggerType: "manual" });
    expect(result).toMatchObject({ status: "timeout", reason: "upstream_timeout", httpStatus: null });
  });

  it("does not follow an HTTPS redirect to an unsafe HTTP/private target", async () => {
    mockProbe(async () => new Response(null, { status: 302, headers: { location: "http://127.0.0.1/internal" } }));
    const result = await runGatewayHealthCheck(env(), gateway("degraded"), { triggerType: "manual" });
    expect(result.status).toBe("degraded");
    expect(result.reason).toBe("redirect_blocked:redirect_protocol_downgrade");
    expect(result.httpStatus).toBe(302);
  });
});
