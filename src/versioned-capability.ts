import { issueCapabilityToken, verifyCapabilityToken, type CapabilityClaims, type CapabilityIssueInput } from "./capability";
import { capabilitySigningKeyring } from "./keyring";
import type { Env } from "./types";

const PREFIX = "cg_cap_";

export async function issueVersionedCapabilityToken(
  env: Pick<Env, "CAPABILITY_SIGNING_KEY" | "CAPABILITY_SIGNING_KEYRING">,
  input: CapabilityIssueInput,
  nowSeconds?: number,
) {
  const ring = capabilitySigningKeyring(env);
  const issued = await issueCapabilityToken(ring.keys[ring.activeKid], input, nowSeconds);
  if (ring.activeKid === "v1") return { ...issued, signingKid: "v1" };

  const encoded = issued.token.slice(PREFIX.length);
  return {
    ...issued,
    token: `${PREFIX}${ring.activeKid}.${encoded}`,
    signingKid: ring.activeKid,
  };
}

export async function verifyVersionedCapabilityToken(
  env: Pick<Env, "CAPABILITY_SIGNING_KEY" | "CAPABILITY_SIGNING_KEYRING">,
  token: string,
  nowSeconds?: number,
): Promise<CapabilityClaims> {
  if (!token.startsWith(PREFIX)) throw new Error("not a ContextGateway capability token");
  const parts = token.slice(PREFIX.length).split(".");
  const ring = capabilitySigningKeyring(env);

  if (parts.length === 2) {
    return verifyCapabilityToken(ring.keys.v1, token, nowSeconds);
  }
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    throw new Error("malformed capability token");
  }

  const [kid, payload, signature] = parts;
  const key = ring.keys[kid];
  if (!key) throw new Error("capability signing key version is not configured");
  return verifyCapabilityToken(key, `${PREFIX}${payload}.${signature}`, nowSeconds);
}
