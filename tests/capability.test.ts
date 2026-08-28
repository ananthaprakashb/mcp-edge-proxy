import { describe, expect, it } from "vitest";
import {
  capabilityArgumentsDigest,
  capabilityArgumentsMatch,
  isCapabilityToken,
  issueCapabilityToken,
  verifyCapabilityToken,
} from "../src/capability";

const signingKey = "test-capability-signing-key-that-is-definitely-long-enough";

function input() {
  return {
    accountId: "acct-1",
    gatewayId: "gw-1",
    apiKeyId: "key-1",
    method: "tools/call",
    name: "demo.allowed",
  } as const;
}

describe("capability tokens", () => {
  it("issues and verifies a short-lived scoped token", async () => {
    const issued = await issueCapabilityToken(signingKey, { ...input(), ttlSeconds: 15 }, 1_000);
    expect(isCapabilityToken(issued.token)).toBe(true);
    const claims = await verifyCapabilityToken(signingKey, issued.token, 1_010);
    expect(claims.gatewayId).toBe("gw-1");
    expect(claims.apiKeyId).toBe("key-1");
    expect(claims.method).toBe("tools/call");
    expect(claims.name).toBe("demo.allowed");
    expect(claims.exp).toBe(1_015);
  });

  it("rejects expired and tampered tokens", async () => {
    const issued = await issueCapabilityToken(signingKey, { ...input(), ttlSeconds: 5 }, 2_000);
    await expect(verifyCapabilityToken(signingKey, issued.token, 2_005)).rejects.toThrow("expired");

    const tampered = `${issued.token.slice(0, -1)}${issued.token.endsWith("A") ? "B" : "A"}`;
    await expect(verifyCapabilityToken(signingKey, tampered, 2_001)).rejects.toThrow("signature");
  });

  it("caps TTL at 300 seconds", async () => {
    await expect(issueCapabilityToken(signingKey, { ...input(), ttlSeconds: 301 }, 3_000)).rejects.toThrow("between 1 and 300");
  });

  it("canonicalizes object keys for exact argument binding", async () => {
    const left = await capabilityArgumentsDigest({ b: 2, a: { y: true, x: "same" } });
    const right = await capabilityArgumentsDigest({ a: { x: "same", y: true }, b: 2 });
    expect(left).toBe(right);

    const issued = await issueCapabilityToken(signingKey, {
      ...input(),
      ttlSeconds: 30,
      arguments: { ticket: "INC-42", priority: "high" },
      bindArguments: true,
    }, 4_000);
    const claims = await verifyCapabilityToken(signingKey, issued.token, 4_001);
    await expect(capabilityArgumentsMatch(claims, { priority: "high", ticket: "INC-42" })).resolves.toBe(true);
    await expect(capabilityArgumentsMatch(claims, { priority: "low", ticket: "INC-42" })).resolves.toBe(false);
  });
});
