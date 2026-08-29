export type NetworkBlockReason =
  | "blocked_hostname"
  | "blocked_ip_literal"
  | "dns_resolution_failed"
  | "dns_unresolved"
  | "resolved_non_public_address"
  | "dns_rebinding_private_target"
  | "redirect_protocol_downgrade"
  | "redirect_target_blocked";

export interface NetworkValidationResult {
  allowed: boolean;
  hostname: string;
  addresses: string[];
  reason?: NetworkBlockReason;
  blockedAddress?: string;
  changedBetweenChecks?: boolean;
}

export type HostResolver = (hostname: string) => Promise<string[]>;

const BLOCKED_HOSTS = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata.google",
  "instance-data",
  "instance-data.ec2.internal",
]);

const BLOCKED_SUFFIXES = [
  ".localhost",
  ".local",
  ".internal",
  ".home.arpa",
  ".invalid",
  ".test",
];

function normalizeHostname(value: string): string {
  return value.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

function ipv4ToInt(value: string): number | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map(Number);
  if (nums.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return (((nums[0] << 24) >>> 0) + (nums[1] << 16) + (nums[2] << 8) + nums[3]) >>> 0;
}

function ipv4InCidr(ip: number, base: number, prefix: number): boolean {
  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (ip & mask) === (base & mask);
}

function parseIpv6(value: string): bigint | null {
  let input = value.toLowerCase();
  if (input.includes("%")) return null;
  const ipv4Match = /(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(input);
  if (ipv4Match) {
    const v4 = ipv4ToInt(ipv4Match[1]);
    if (v4 === null) return null;
    const high = ((v4 >>> 16) & 0xffff).toString(16);
    const low = (v4 & 0xffff).toString(16);
    input = input.slice(0, input.length - ipv4Match[1].length) + `${high}:${low}`;
  }

  const double = input.indexOf("::");
  if (double !== input.lastIndexOf("::")) return null;
  const left = double >= 0 ? input.slice(0, double).split(":").filter(Boolean) : input.split(":");
  const right = double >= 0 ? input.slice(double + 2).split(":").filter(Boolean) : [];
  if (double < 0 && left.length !== 8) return null;
  if (double >= 0 && left.length + right.length >= 8) return null;
  const fill = double >= 0 ? Array(8 - left.length - right.length).fill("0") : [];
  const parts = [...left, ...fill, ...right];
  if (parts.length !== 8 || parts.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  return parts.reduce((acc, part) => (acc << 16n) | BigInt(parseInt(part, 16)), 0n);
}

function ipv6Base(value: string): bigint {
  const parsed = parseIpv6(value);
  if (parsed === null) throw new Error(`Invalid IPv6 base: ${value}`);
  return parsed;
}

function ipv6InCidr(ip: bigint, base: bigint, prefix: number): boolean {
  if (prefix === 0) return true;
  const shift = BigInt(128 - prefix);
  return (ip >> shift) === (base >> shift);
}

const IPV4_BLOCKS: Array<[string, number, string]> = [
  ["0.0.0.0", 8, "unspecified"],
  ["10.0.0.0", 8, "private"],
  ["100.64.0.0", 10, "carrier-grade-nat"],
  ["127.0.0.0", 8, "loopback"],
  ["169.254.0.0", 16, "link-local"],
  ["172.16.0.0", 12, "private"],
  ["192.0.0.0", 24, "protocol-special"],
  ["192.0.2.0", 24, "documentation"],
  ["192.88.99.0", 24, "protocol-special"],
  ["192.168.0.0", 16, "private"],
  ["198.18.0.0", 15, "benchmark"],
  ["198.51.100.0", 24, "documentation"],
  ["203.0.113.0", 24, "documentation"],
  ["224.0.0.0", 4, "multicast"],
  ["240.0.0.0", 4, "reserved"],
];

const IPV6_BLOCKS: Array<[bigint, number, string]> = [
  [ipv6Base("::"), 128, "unspecified"],
  [ipv6Base("::1"), 128, "loopback"],
  [ipv6Base("64:ff9b:1::"), 48, "local-nat64"],
  [ipv6Base("100::"), 64, "discard"],
  [ipv6Base("2001:2::"), 48, "benchmark"],
  [ipv6Base("2001:db8::"), 32, "documentation"],
  [ipv6Base("fc00::"), 7, "private"],
  [ipv6Base("fe80::"), 10, "link-local"],
  [ipv6Base("fec0::"), 10, "site-local"],
  [ipv6Base("ff00::"), 8, "multicast"],
];

export function classifyIpAddress(value: string): { public: boolean; category: string } | null {
  const v4 = ipv4ToInt(value);
  if (v4 !== null) {
    if (value === "169.254.169.254") return { public: false, category: "cloud-metadata" };
    for (const [baseText, prefix, category] of IPV4_BLOCKS) {
      const base = ipv4ToInt(baseText)!;
      if (ipv4InCidr(v4, base, prefix)) return { public: false, category };
    }
    return { public: true, category: "public-ipv4" };
  }

  const v6 = parseIpv6(value);
  if (v6 === null) return null;

  const mappedBase = ipv6Base("::ffff:0:0");
  if (ipv6InCidr(v6, mappedBase, 96)) {
    const embedded = Number(v6 & 0xffffffffn) >>> 0;
    const v4Text = `${(embedded >>> 24) & 255}.${(embedded >>> 16) & 255}.${(embedded >>> 8) & 255}.${embedded & 255}`;
    const mapped = classifyIpAddress(v4Text);
    return mapped && !mapped.public ? mapped : { public: true, category: "public-ipv4-mapped" };
  }

  const nat64Base = ipv6Base("64:ff9b::");
  if (ipv6InCidr(v6, nat64Base, 96)) {
    const embedded = Number(v6 & 0xffffffffn) >>> 0;
    const v4Text = `${(embedded >>> 24) & 255}.${(embedded >>> 16) & 255}.${(embedded >>> 8) & 255}.${embedded & 255}`;
    const mapped = classifyIpAddress(v4Text);
    if (mapped && !mapped.public) return { public: false, category: `nat64-${mapped.category}` };
  }

  for (const [base, prefix, category] of IPV6_BLOCKS) {
    if (ipv6InCidr(v6, base, prefix)) return { public: false, category };
  }
  return { public: true, category: "public-ipv6" };
}

export function assertStaticNetworkTarget(hostnameValue: string): void {
  const hostname = normalizeHostname(hostnameValue);
  if (!hostname || hostname.includes("%")) throw new Error("Upstream hostname is invalid");
  if (BLOCKED_HOSTS.has(hostname) || BLOCKED_SUFFIXES.some((suffix) => hostname.endsWith(suffix))) {
    throw new Error("Local, internal, and cloud-metadata upstream hostnames are blocked");
  }
  const ip = classifyIpAddress(hostname);
  if (ip && !ip.public) {
    throw new Error(`Non-public upstream IP addresses are blocked (${ip.category})`);
  }
}

interface DnsJsonAnswer {
  type?: number;
  data?: string;
}
interface DnsJsonResponse {
  Status?: number;
  Answer?: DnsJsonAnswer[];
}

async function queryDnsJson(hostname: string, type: "A" | "AAAA"): Promise<string[]> {
  const url = new URL("https://cloudflare-dns.com/dns-query");
  url.searchParams.set("name", hostname);
  url.searchParams.set("type", type);
  const response = await fetch(url.toString(), {
    headers: { accept: "application/dns-json", "cache-control": "no-cache" },
    signal: AbortSignal.timeout(2500),
  });
  if (!response.ok) throw new Error(`DNS over HTTPS returned HTTP ${response.status}`);
  const body = await response.json() as DnsJsonResponse;
  if (body.Status !== 0 && body.Status !== 3) throw new Error(`DNS resolver status ${body.Status}`);
  const wantedType = type === "A" ? 1 : 28;
  return (body.Answer ?? [])
    .filter((answer) => answer.type === wantedType && typeof answer.data === "string")
    .map((answer) => answer.data!.trim());
}

export async function resolvePublicDns(hostname: string): Promise<string[]> {
  const [v4, v6] = await Promise.all([queryDnsJson(hostname, "A"), queryDnsJson(hostname, "AAAA")]);
  return [...new Set([...v4, ...v6])].sort();
}

function blockedResolvedAddress(addresses: string[]): string | null {
  for (const address of addresses) {
    const classification = classifyIpAddress(address);
    if (!classification || !classification.public) return address;
  }
  return null;
}

export async function validateResolvedNetworkTarget(
  url: URL,
  resolver: HostResolver = resolvePublicDns,
): Promise<NetworkValidationResult> {
  const hostname = normalizeHostname(url.hostname);
  try {
    assertStaticNetworkTarget(hostname);
  } catch {
    return { allowed: false, hostname, addresses: [], reason: classifyIpAddress(hostname) ? "blocked_ip_literal" : "blocked_hostname" };
  }

  const literal = classifyIpAddress(hostname);
  if (literal) return { allowed: literal.public, hostname, addresses: [hostname], ...(literal.public ? {} : { reason: "blocked_ip_literal" as const, blockedAddress: hostname }) };

  let first: string[];
  let second: string[];
  try {
    first = await resolver(hostname);
    if (!first.length) return { allowed: false, hostname, addresses: [], reason: "dns_unresolved" };
    const firstBlocked = blockedResolvedAddress(first);
    if (firstBlocked) return { allowed: false, hostname, addresses: first, blockedAddress: firstBlocked, reason: "resolved_non_public_address" };

    second = await resolver(hostname);
    if (!second.length) return { allowed: false, hostname, addresses: first, reason: "dns_unresolved" };
    const secondBlocked = blockedResolvedAddress(second);
    if (secondBlocked) {
      return {
        allowed: false,
        hostname,
        addresses: second,
        blockedAddress: secondBlocked,
        reason: "dns_rebinding_private_target",
        changedBetweenChecks: true,
      };
    }
  } catch {
    return { allowed: false, hostname, addresses: [], reason: "dns_resolution_failed" };
  }

  const changedBetweenChecks = first.join(",") !== second.join(",");
  return { allowed: true, hostname, addresses: second, changedBetweenChecks };
}

export async function validateRedirectTarget(
  sourceUrl: URL,
  location: string,
  resolver: HostResolver = resolvePublicDns,
): Promise<{ target: URL | null; validation: NetworkValidationResult }> {
  let target: URL;
  try {
    target = new URL(location, sourceUrl);
  } catch {
    return { target: null, validation: { allowed: false, hostname: "", addresses: [], reason: "redirect_target_blocked" } };
  }
  if (sourceUrl.protocol === "https:" && target.protocol !== "https:") {
    return { target, validation: { allowed: false, hostname: normalizeHostname(target.hostname), addresses: [], reason: "redirect_protocol_downgrade" } };
  }
  if (target.username || target.password || (target.protocol !== "https:" && target.protocol !== "http:")) {
    return { target, validation: { allowed: false, hostname: normalizeHostname(target.hostname), addresses: [], reason: "redirect_target_blocked" } };
  }
  return { target, validation: await validateResolvedNetworkTarget(target, resolver) };
}
