import { secureTokenEquals, sha256Hex } from "./crypto";
import type { D1Database } from "./types";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const PREFIX = "cg_cap_";
export const MAX_CAPABILITY_TTL_SECONDS = 300;
export const DEFAULT_CAPABILITY_TTL_SECONDS = 30;

export interface CapabilityClaims {
  v: 1;
  accountId: string;
  gatewayId: string;
  apiKeyId: string;
  method: string;
  name: string | null;
  jti: string;
  iat: number;
  exp: number;
  argumentsSha256?: string;
}

export interface CapabilityIssueInput {
  accountId: string;
  gatewayId: string;
  apiKeyId: string;
  method: string;
  name: string | null;
  ttlSeconds?: number;
  arguments?: unknown;
  bindArguments?: boolean;
}

function signingKeyBytes(signingKey: string): Uint8Array {
  if (!signingKey || signingKey.length < 32) {
    throw new Error("CAPABILITY_SIGNING_KEY must contain at least 32 characters");
  }
  return encoder.encode(signingKey);
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function randomId(): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(18)));
}

async function hmacSha256(signingKey: string, value: string): Promise<Uint8Array> {
  const raw = signingKeyBytes(signingKey);
  const key = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return new Uint8Array(signature);
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Capability arguments contain a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new Error("Capability arguments must be JSON-compatible");
}

export async function capabilityArgumentsDigest(value: unknown): Promise<string> {
  return sha256Hex(canonicalJson(value));
}

function validClaims(value: unknown): value is CapabilityClaims {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const claims = value as Partial<CapabilityClaims>;
  return claims.v === 1
    && typeof claims.accountId === "string" && claims.accountId.length > 0
    && typeof claims.gatewayId === "string" && claims.gatewayId.length > 0
    && typeof claims.apiKeyId === "string" && claims.apiKeyId.length > 0
    && typeof claims.method === "string" && claims.method.length > 0
    && (claims.name === null || typeof claims.name === "string")
    && typeof claims.jti === "string" && claims.jti.length >= 16
    && typeof claims.iat === "number" && Number.isInteger(claims.iat)
    && typeof claims.exp === "number" && Number.isInteger(claims.exp)
    && (claims.argumentsSha256 === undefined || (typeof claims.argumentsSha256 === "string" && /^[0-9a-f]{64}$/.test(claims.argumentsSha256)));
}

export function isCapabilityToken(token: string): boolean {
  return token.startsWith(PREFIX);
}

export async function issueCapabilityToken(
  signingKey: string,
  input: CapabilityIssueInput,
  nowSeconds = Math.floor(Date.now() / 1000),
): Promise<{ token: string; claims: CapabilityClaims; expiresIn: number }> {
  const ttlSeconds = input.ttlSeconds ?? DEFAULT_CAPABILITY_TTL_SECONDS;
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > MAX_CAPABILITY_TTL_SECONDS) {
    throw new Error(`ttlSeconds must be an integer between 1 and ${MAX_CAPABILITY_TTL_SECONDS}`);
  }
  if (!input.method.trim()) throw new Error("method is required");
  if (input.name !== null && !input.name.trim()) throw new Error("name must be null or a non-empty string");

  const claims: CapabilityClaims = {
    v: 1,
    accountId: input.accountId,
    gatewayId: input.gatewayId,
    apiKeyId: input.apiKeyId,
    method: input.method,
    name: input.name,
    jti: randomId(),
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds,
  };
  if (input.bindArguments) claims.argumentsSha256 = await capabilityArgumentsDigest(input.arguments);

  const payload = bytesToBase64Url(encoder.encode(JSON.stringify(claims)));
  const signature = bytesToBase64Url(await hmacSha256(signingKey, payload));
  return { token: `${PREFIX}${payload}.${signature}`, claims, expiresIn: ttlSeconds };
}

export async function verifyCapabilityToken(
  signingKey: string,
  token: string,
  nowSeconds = Math.floor(Date.now() / 1000),
): Promise<CapabilityClaims> {
  if (!isCapabilityToken(token)) throw new Error("not a ContextGateway capability token");
  const encoded = token.slice(PREFIX.length);
  const parts = encoded.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) throw new Error("malformed capability token");

  const expected = bytesToBase64Url(await hmacSha256(signingKey, parts[0]));
  if (!(await secureTokenEquals(parts[1], expected))) throw new Error("invalid capability signature");

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoder.decode(base64UrlToBytes(parts[0]))) as unknown;
  } catch {
    throw new Error("invalid capability claims");
  }
  if (!validClaims(parsed)) throw new Error("invalid capability claims");
  if (parsed.exp <= nowSeconds) throw new Error("capability expired");
  if (parsed.iat > nowSeconds + 30) throw new Error("capability issued in the future");
  if (parsed.exp - parsed.iat > MAX_CAPABILITY_TTL_SECONDS) throw new Error("capability TTL exceeds policy maximum");
  return parsed;
}

export async function capabilityArgumentsMatch(claims: CapabilityClaims, value: unknown): Promise<boolean> {
  if (!claims.argumentsSha256) return true;
  const actual = await capabilityArgumentsDigest(value);
  return secureTokenEquals(actual, claims.argumentsSha256);
}

export async function consumeCapability(db: D1Database, claims: CapabilityClaims): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000);
  // Keep the replay table bounded without making cleanup availability part of
  // the authorization decision. The insert below remains the fail-closed step.
  try {
    await db.prepare(`DELETE FROM capability_replays WHERE expires_at < ?`).bind(now - 3600).run();
  } catch {
    // Ignore cleanup failure; the atomic insert still determines authorization.
  }

  const result = await db
    .prepare(
      `INSERT OR IGNORE INTO capability_replays
       (jti, account_id, gateway_id, api_key_id, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .bind(claims.jti, claims.accountId, claims.gatewayId, claims.apiKeyId, claims.exp)
    .run();
  return Number(result.meta?.changes ?? 0) === 1;
}
