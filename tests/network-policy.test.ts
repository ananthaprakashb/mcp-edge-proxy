import { describe, expect, it } from "vitest";
import {
  assertStaticNetworkTarget,
  classifyIpAddress,
  validateRedirectTarget,
  validateResolvedNetworkTarget,
  type HostResolver,
} from "../src/network-policy";
import { validateUpstreamUrl } from "../src/security";

describe("network SSRF policy", () => {
  it("blocks IPv4 private, loopback, link-local, CGNAT, metadata, benchmark, and reserved ranges", () => {
    for (const address of [
      "0.0.0.1",
      "10.1.2.3",
      "100.100.100.200",
      "127.0.0.1",
      "169.254.169.254",
      "172.16.4.1",
      "192.168.10.2",
      "198.18.0.1",
      "224.0.0.1",
      "255.255.255.255",
    ]) {
      expect(classifyIpAddress(address)?.public, address).toBe(false);
    }
  });

  it("blocks non-canonical URL spellings of loopback IPv4", () => {
    for (const url of [
      "https://2130706433/mcp",
      "https://0x7f000001/mcp",
      "https://0177.0.0.1/mcp",
      "https://127.1/mcp",
    ]) {
      expect(() => validateUpstreamUrl(url, false), url).toThrow();
    }
  });

  it("blocks IPv6 local, mapped-private, NAT64-private, documentation, and multicast ranges", () => {
    for (const address of [
      "::",
      "::1",
      "::ffff:127.0.0.1",
      "64:ff9b::a9fe:a9fe",
      "100::1",
      "2001:db8::1",
      "fc00::1",
      "fd12:3456::1",
      "fe80::1",
      "ff02::1",
    ]) {
      expect(classifyIpAddress(address)?.public, address).toBe(false);
    }
  });

  it("allows representative public IPv4 and IPv6 addresses", () => {
    expect(classifyIpAddress("1.1.1.1")).toMatchObject({ public: true });
    expect(classifyIpAddress("8.8.8.8")).toMatchObject({ public: true });
    expect(classifyIpAddress("2606:4700:4700::1111")).toMatchObject({ public: true });
  });

  it("blocks internal and metadata hostnames before DNS", () => {
    for (const hostname of [
      "localhost",
      "api.localhost",
      "metadata.google.internal",
      "instance-data.ec2.internal",
      "service.internal",
      "printer.local",
      "router.home.arpa",
    ]) {
      expect(() => assertStaticNetworkTarget(hostname), hostname).toThrow();
    }
    expect(() => assertStaticNetworkTarget("api.example.com")).not.toThrow();
  });

  it("blocks a hostname when any resolved address is non-public", async () => {
    const resolver: HostResolver = async () => ["1.1.1.1", "10.0.0.8"];
    const result = await validateResolvedNetworkTarget(new URL("https://mcp.example.com/rpc"), resolver);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("resolved_non_public_address");
    expect(result.blockedAddress).toBe("10.0.0.8");
  });

  it("detects a public-to-private DNS rebinding transition", async () => {
    let calls = 0;
    const resolver: HostResolver = async () => {
      calls += 1;
      return calls === 1 ? ["1.1.1.1"] : ["192.168.1.20"];
    };
    const result = await validateResolvedNetworkTarget(new URL("https://mcp.example.com/rpc"), resolver);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("dns_rebinding_private_target");
    expect(result.changedBetweenChecks).toBe(true);
  });

  it("allows public DNS answers even when a CDN rotates between public addresses", async () => {
    let calls = 0;
    const resolver: HostResolver = async () => {
      calls += 1;
      return calls === 1 ? ["1.1.1.1"] : ["8.8.8.8"];
    };
    const result = await validateResolvedNetworkTarget(new URL("https://mcp.example.com/rpc"), resolver);
    expect(result.allowed).toBe(true);
    expect(result.changedBetweenChecks).toBe(true);
  });

  it("fails closed on DNS errors and empty answers", async () => {
    const failing: HostResolver = async () => { throw new Error("resolver unavailable"); };
    await expect(validateResolvedNetworkTarget(new URL("https://mcp.example.com"), failing)).resolves.toMatchObject({
      allowed: false,
      reason: "dns_resolution_failed",
    });
    const empty: HostResolver = async () => [];
    await expect(validateResolvedNetworkTarget(new URL("https://mcp.example.com"), empty)).resolves.toMatchObject({
      allowed: false,
      reason: "dns_unresolved",
    });
  });

  it("blocks redirects to private targets and HTTPS-to-HTTP downgrades", async () => {
    const privateResolver: HostResolver = async () => ["10.0.0.2"];
    const privateRedirect = await validateRedirectTarget(
      new URL("https://public.example.com/mcp"),
      "https://internal-target.example.com/mcp",
      privateResolver,
    );
    expect(privateRedirect.validation.allowed).toBe(false);
    expect(privateRedirect.validation.reason).toBe("resolved_non_public_address");

    const downgrade = await validateRedirectTarget(
      new URL("https://public.example.com/mcp"),
      "http://public.example.com/mcp",
      async () => ["1.1.1.1"],
    );
    expect(downgrade.validation.allowed).toBe(false);
    expect(downgrade.validation.reason).toBe("redirect_protocol_downgrade");
  });

  it("allows a validated HTTPS redirect to public addresses", async () => {
    const result = await validateRedirectTarget(
      new URL("https://public.example.com/mcp"),
      "/mcp/v2",
      async () => ["1.1.1.1"],
    );
    expect(result.validation.allowed).toBe(true);
    expect(result.target?.pathname).toBe("/mcp/v2");
  });
});
