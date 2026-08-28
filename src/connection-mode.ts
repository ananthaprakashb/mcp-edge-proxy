import type { UpstreamConnectionMode } from "./types";

export function parseConnectionMode(value: unknown): UpstreamConnectionMode {
  if (value === undefined || value === null || value === "public") return "public";
  if (value === "cloudflare_access") return value;
  throw new Error("connectionMode must be one of: public, cloudflare_access");
}

function optionalCredential(value: unknown, field: string): string | null {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || value.trim().length === 0 || value.length > 4096) {
    throw new Error(`${field} must be a non-empty string no longer than 4096 characters`);
  }
  return value.trim();
}

export function applyConnectionCredentials(
  mode: UpstreamConnectionMode,
  headers: Record<string, string>,
  input: { accessClientId?: unknown; accessClientSecret?: unknown },
): Record<string, string> {
  const clientId = optionalCredential(input.accessClientId, "accessClientId");
  const clientSecret = optionalCredential(input.accessClientSecret, "accessClientSecret");

  if (mode === "public") {
    if (clientId || clientSecret) {
      throw new Error("Cloudflare Access credentials require connectionMode=cloudflare_access");
    }
    return { ...headers };
  }

  if (!clientId || !clientSecret) {
    throw new Error("cloudflare_access gateways require both accessClientId and accessClientSecret");
  }

  return {
    ...headers,
    "CF-Access-Client-Id": clientId,
    "CF-Access-Client-Secret": clientSecret,
  };
}
