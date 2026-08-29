import { decryptString, encryptString } from "./crypto";
import type { Env } from "./types";

export interface VersionedEncryptionEnvelope {
  ciphertext: string;
  iv: string;
  version: number;
}

export interface CapabilitySigningKeyring {
  activeKid: string;
  keys: Record<string, string>;
}

type RawKeyring = {
  active?: unknown;
  keys?: unknown;
};

function parseJsonKeyring(value: string | undefined, label: string): RawKeyring | null {
  if (!value) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error(`${label} must be valid JSON`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return parsed as RawKeyring;
}

function parseKeys(value: unknown, label: string): Record<string, string> {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label}.keys must be a JSON object`);
  }
  const result: Record<string, string> = {};
  for (const [key, secret] of Object.entries(value as Record<string, unknown>)) {
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(key)) throw new Error(`${label} contains an invalid key id`);
    if (typeof secret !== "string" || secret.length < 32) throw new Error(`${label} key ${key} must contain at least 32 characters`);
    result[key] = secret;
  }
  return result;
}

export function upstreamEncryptionKeyring(env: Pick<Env, "UPSTREAM_ENCRYPTION_KEY" | "UPSTREAM_ENCRYPTION_KEYRING">): {
  activeVersion: number;
  keys: Record<number, string>;
} {
  const keys: Record<number, string> = { 1: env.UPSTREAM_ENCRYPTION_KEY };
  const parsed = parseJsonKeyring(env.UPSTREAM_ENCRYPTION_KEYRING, "UPSTREAM_ENCRYPTION_KEYRING");
  if (!parsed) return { activeVersion: 1, keys };

  const configured = parseKeys(parsed.keys, "UPSTREAM_ENCRYPTION_KEYRING");
  for (const [id, secret] of Object.entries(configured)) {
    if (!/^\d+$/.test(id) || Number(id) < 2) throw new Error("Upstream encryption key versions in the keyring must be integers >= 2");
    keys[Number(id)] = secret;
  }
  const activeVersion = parsed.active === undefined ? 1 : Number(parsed.active);
  if (!Number.isInteger(activeVersion) || activeVersion < 1 || !keys[activeVersion]) {
    throw new Error("UPSTREAM_ENCRYPTION_KEYRING.active must identify a configured key version");
  }
  return { activeVersion, keys };
}

export async function encryptUpstreamSecret(env: Pick<Env, "UPSTREAM_ENCRYPTION_KEY" | "UPSTREAM_ENCRYPTION_KEYRING">, plaintext: string): Promise<VersionedEncryptionEnvelope> {
  const ring = upstreamEncryptionKeyring(env);
  const encrypted = await encryptString(plaintext, ring.keys[ring.activeVersion]);
  return { ...encrypted, version: ring.activeVersion };
}

export async function decryptUpstreamSecret(
  env: Pick<Env, "UPSTREAM_ENCRYPTION_KEY" | "UPSTREAM_ENCRYPTION_KEYRING">,
  envelope: VersionedEncryptionEnvelope,
): Promise<string> {
  const ring = upstreamEncryptionKeyring(env);
  const key = ring.keys[envelope.version];
  if (!key) throw new Error(`No upstream encryption key is configured for version ${envelope.version}`);
  return decryptString(envelope.ciphertext, envelope.iv, key);
}

export function capabilitySigningKeyring(env: Pick<Env, "CAPABILITY_SIGNING_KEY" | "CAPABILITY_SIGNING_KEYRING">): CapabilitySigningKeyring {
  const keys: Record<string, string> = { v1: env.CAPABILITY_SIGNING_KEY };
  const parsed = parseJsonKeyring(env.CAPABILITY_SIGNING_KEYRING, "CAPABILITY_SIGNING_KEYRING");
  if (!parsed) return { activeKid: "v1", keys };

  Object.assign(keys, parseKeys(parsed.keys, "CAPABILITY_SIGNING_KEYRING"));
  const activeKid = parsed.active === undefined ? "v1" : String(parsed.active);
  if (!keys[activeKid]) throw new Error("CAPABILITY_SIGNING_KEYRING.active must identify a configured signing key");
  return { activeKid, keys };
}

export function publicKeyringMetadata(env: Pick<Env, "UPSTREAM_ENCRYPTION_KEY" | "UPSTREAM_ENCRYPTION_KEYRING" | "CAPABILITY_SIGNING_KEY" | "CAPABILITY_SIGNING_KEYRING">) {
  const encryption = upstreamEncryptionKeyring(env);
  const signing = capabilitySigningKeyring(env);
  return {
    upstreamEncryption: {
      activeVersion: encryption.activeVersion,
      configuredVersions: Object.keys(encryption.keys).map(Number).sort((a, b) => a - b),
    },
    capabilitySigning: {
      activeKid: signing.activeKid,
      configuredKids: Object.keys(signing.keys).sort(),
    },
  };
}
