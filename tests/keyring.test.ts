import { describe, expect, it } from "vitest";
import { capabilitySigningKeyring, decryptUpstreamSecret, encryptUpstreamSecret, publicKeyringMetadata, upstreamEncryptionKeyring } from "../src/keyring";

const encryptionV1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const encryptionV2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const signingV1 = "legacy-capability-signing-key-that-is-long-enough-v1";
const signingV2 = "rotated-capability-signing-key-that-is-long-enough-v2";

describe("secret keyrings", () => {
  it("defaults to legacy v1 secrets without requiring new configuration", () => {
    const encryption = upstreamEncryptionKeyring({ UPSTREAM_ENCRYPTION_KEY: encryptionV1 });
    const signing = capabilitySigningKeyring({ CAPABILITY_SIGNING_KEY: signingV1 });
    expect(encryption.activeVersion).toBe(1);
    expect(encryption.keys[1]).toBe(encryptionV1);
    expect(signing.activeKid).toBe("v1");
    expect(signing.keys.v1).toBe(signingV1);
  });

  it("encrypts with the active generation and decrypts older generations", async () => {
    const env = {
      UPSTREAM_ENCRYPTION_KEY: encryptionV1,
      UPSTREAM_ENCRYPTION_KEYRING: JSON.stringify({ active: 2, keys: { 2: encryptionV2 } }),
    };
    const encrypted = await encryptUpstreamSecret(env, "secret headers");
    expect(encrypted.version).toBe(2);
    await expect(decryptUpstreamSecret(env, encrypted)).resolves.toBe("secret headers");

    const old = await encryptUpstreamSecret({ UPSTREAM_ENCRYPTION_KEY: encryptionV1 }, "legacy");
    await expect(decryptUpstreamSecret(env, old)).resolves.toBe("legacy");
  });

  it("publishes identifiers only and rejects missing active keys", () => {
    const env = {
      UPSTREAM_ENCRYPTION_KEY: encryptionV1,
      UPSTREAM_ENCRYPTION_KEYRING: JSON.stringify({ active: 2, keys: { 2: encryptionV2 } }),
      CAPABILITY_SIGNING_KEY: signingV1,
      CAPABILITY_SIGNING_KEYRING: JSON.stringify({ active: "v2", keys: { v2: signingV2 } }),
    };
    expect(publicKeyringMetadata(env)).toEqual({
      upstreamEncryption: { activeVersion: 2, configuredVersions: [1, 2] },
      capabilitySigning: { activeKid: "v2", configuredKids: ["v1", "v2"] },
    });
    expect(JSON.stringify(publicKeyringMetadata(env))).not.toContain(signingV2);
    expect(() => capabilitySigningKeyring({ CAPABILITY_SIGNING_KEY: signingV1, CAPABILITY_SIGNING_KEYRING: '{"active":"v2","keys":{}}' })).toThrow("active");
  });
});
