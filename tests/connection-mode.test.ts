import { describe, expect, it } from "vitest";
import { applyConnectionCredentials, parseConnectionMode } from "../src/connection-mode";
import { buildUpstreamHeaders } from "../src/security";

describe("private upstream connection modes", () => {
  it("keeps existing gateways public by default", () => {
    expect(parseConnectionMode(undefined)).toBe("public");
    expect(parseConnectionMode("public")).toBe("public");
    expect(parseConnectionMode("cloudflare_access")).toBe("cloudflare_access");
    expect(() => parseConnectionMode("private")).toThrow(/connectionMode/);
  });

  it("requires a complete Cloudflare Access service-token pair", () => {
    expect(() => applyConnectionCredentials("cloudflare_access", {}, {
      accessClientId: "client-id",
    })).toThrow(/both accessClientId and accessClientSecret/);
  });

  it("injects dedicated Access credentials over generic header values", () => {
    const headers = applyConnectionCredentials("cloudflare_access", {
      "X-Upstream-Key": "safe",
      "CF-Access-Client-Id": "untrusted-id",
    }, {
      accessClientId: "stored-id",
      accessClientSecret: "stored-secret",
    });
    expect(headers["X-Upstream-Key"]).toBe("safe");
    expect(headers["CF-Access-Client-Id"]).toBe("stored-id");
    expect(headers["CF-Access-Client-Secret"]).toBe("stored-secret");
  });

  it("does not accept Access credentials on a public-mode gateway", () => {
    expect(() => applyConnectionCredentials("public", {}, {
      accessClientId: "stored-id",
      accessClientSecret: "stored-secret",
    })).toThrow(/connectionMode=cloudflare_access/);
  });

  it("strips caller Access headers before injecting stored credentials", () => {
    const request = new Request("https://contextgateway.test/v1/mcp/gateway", {
      headers: {
        Authorization: "Bearer caller-secret",
        "CF-Access-Client-Id": "attacker-id",
        "CF-Access-Client-Secret": "attacker-secret",
      },
    });
    const headers = buildUpstreamHeaders(request, {
      "CF-Access-Client-Id": "stored-id",
      "CF-Access-Client-Secret": "stored-secret",
    });
    expect(headers.get("authorization")).toBeNull();
    expect(headers.get("CF-Access-Client-Id")).toBe("stored-id");
    expect(headers.get("CF-Access-Client-Secret")).toBe("stored-secret");
  });
});
