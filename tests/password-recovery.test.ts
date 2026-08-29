import { describe, expect, it } from "vitest";
import { handlePasswordRecoveryApi } from "../src/password-recovery-api";
import type { Env, ExecutionContextLike } from "../src/types";

function env(overrides: Partial<Env> = {}): Env {
  return {
    RESEND_API_KEY: undefined,
    AUTH_EMAIL_FROM: undefined,
    ...overrides,
  } as unknown as Env;
}

const ctx: ExecutionContextLike = {
  waitUntil() {},
};

describe("password recovery API", () => {
  it("reports when transactional email is not configured", async () => {
    const request = new Request("https://contextgateway.sharecapsule.org/v1/app/password-recovery/status");
    const response = await handlePasswordRecoveryApi(request, env(), ctx, "/v1/app/password-recovery/status");
    expect(response?.status).toBe(200);
    await expect(response?.json()).resolves.toEqual({ configured: false });
  });

  it("fails visibly instead of pretending reset email was sent when email is not configured", async () => {
    const request = new Request("https://contextgateway.sharecapsule.org/v1/app/password-recovery/request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "person@example.com" }),
    });
    const response = await handlePasswordRecoveryApi(request, env(), ctx, "/v1/app/password-recovery/request");
    expect(response?.status).toBe(503);
    const body = await response?.json() as { error?: { code?: string } };
    expect(body.error?.code).toBe("password_recovery_unavailable");
  });

  it("rejects malformed email before invoking Better Auth", async () => {
    const request = new Request("https://contextgateway.sharecapsule.org/v1/app/password-recovery/request", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "not-an-email" }),
    });
    const response = await handlePasswordRecoveryApi(
      request,
      env({ RESEND_API_KEY: "re_test", AUTH_EMAIL_FROM: "ContextGateway <security@auth.sharecapsule.org>" }),
      ctx,
      "/v1/app/password-recovery/request",
    );
    expect(response?.status).toBe(400);
  });
});
