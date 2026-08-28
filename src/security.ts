const FORBIDDEN_UPSTREAM_HEADERS = new Set([
  "connection",
  "content-length",
  "cookie",
  "host",
  "proxy-authorization",
  "transfer-encoding",
  "upgrade",
]);

const STRIPPED_CALLER_HEADERS = [
  "authorization",
  "cookie",
  "proxy-authorization",
  "cf-access-client-id",
  "cf-access-client-secret",
  "x-contextgateway-control-token",
];

function isPrivateIpv4(hostname: string): boolean {
  const parts = hostname.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  const [a, b] = parts;
  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 0
  );
}

export function validateUpstreamUrl(value: string, allowInsecure: boolean): URL {
  const url = new URL(value);
  if (url.username || url.password) throw new Error("Upstream URLs must not contain embedded credentials");
  if (url.protocol !== "https:" && !(allowInsecure && url.protocol === "http:")) {
    throw new Error("Upstream URLs must use HTTPS");
  }

  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname === "::1" ||
    hostname === "metadata.google.internal" ||
    hostname === "169.254.169.254" ||
    isPrivateIpv4(hostname)
  ) {
    throw new Error("Direct loopback, link-local, and private-network upstreams are blocked; use a secure tunnel hostname");
  }
  return url;
}

export function validateUpstreamHeaders(value: unknown): Record<string, string> {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("upstreamHeaders must be an object of string header values");
  }

  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > 20) throw new Error("A gateway can configure at most 20 upstream headers");

  const headers: Record<string, string> = {};
  for (const [name, rawValue] of entries) {
    const normalized = name.toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(name)) throw new Error(`Invalid upstream header name: ${name}`);
    if (FORBIDDEN_UPSTREAM_HEADERS.has(normalized)) throw new Error(`Upstream header is not configurable: ${name}`);
    if (typeof rawValue !== "string" || rawValue.length > 4096) {
      throw new Error(`Upstream header ${name} must be a string no longer than 4096 characters`);
    }
    headers[name] = rawValue;
  }
  return headers;
}

export function buildUpstreamHeaders(request: Request, injectedHeaders: Record<string, string>): Headers {
  const headers = new Headers(request.headers);
  for (const header of STRIPPED_CALLER_HEADERS) headers.delete(header);
  for (const [name, value] of Object.entries(injectedHeaders)) headers.set(name, value);
  return headers;
}
