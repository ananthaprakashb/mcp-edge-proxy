import { createAuth } from "./auth";
import { passwordResetEmailConfigured } from "./email";
import type { Env, ExecutionContextLike } from "./types";

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function canonicalBaseUrl(env: Env, request: Request): string {
  return (env.BETTER_AUTH_URL || new URL(request.url).origin).replace(/\/$/, "");
}

function validEmail(value: unknown): value is string {
  return typeof value === "string"
    && value.length <= 320
    && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

export async function handlePasswordRecoveryApi(
  request: Request,
  env: Env,
  ctx: ExecutionContextLike,
  path: string,
): Promise<Response | null> {
  if (path === "/v1/app/password-recovery/status" && request.method === "GET") {
    return json({ configured: passwordResetEmailConfigured(env) });
  }

  if (path !== "/v1/app/password-recovery/request" || request.method !== "POST") return null;

  if (!passwordResetEmailConfigured(env)) {
    return json({
      error: {
        code: "password_recovery_unavailable",
        message: "Password recovery email delivery is not configured.",
      },
    }, 503);
  }

  let body: Record<string, unknown>;
  try {
    const parsed = await request.json() as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid_body");
    body = parsed as Record<string, unknown>;
  } catch {
    return json({ error: { code: "invalid_request", message: "A valid email address is required." } }, 400);
  }

  if (!validEmail(body.email)) {
    return json({ error: { code: "invalid_request", message: "A valid email address is required." } }, 400);
  }

  const email = body.email.trim().toLowerCase();
  const auth = createAuth(env, request, ctx);

  try {
    await auth.api.requestPasswordReset({
      body: {
        email,
        redirectTo: `${canonicalBaseUrl(env, request)}/reset-password`,
      },
    });
  } catch {
    console.error("ContextGateway password reset request failed");
    return json({
      error: {
        code: "password_recovery_failed",
        message: "Password recovery could not be started. Please try again.",
      },
    }, 502);
  }

  // Deliberately generic: never disclose whether the submitted account exists.
  return json({ accepted: true }, 202);
}
