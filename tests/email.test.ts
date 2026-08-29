import { describe, expect, it } from "vitest";
import { buildPasswordResetEmail, passwordResetEmailConfigured } from "../src/email";
import type { Env } from "../src/types";

describe("password reset email", () => {
  it("includes the reset URL in both text and HTML safely", () => {
    const url = "https://contextgateway.sharecapsule.org/api/auth/reset-password/token?callbackURL=https%3A%2F%2Fcontextgateway.sharecapsule.org%2Freset-password&x=1";
    const email = buildPasswordResetEmail(url);
    expect(email.subject).toContain("ContextGateway");
    expect(email.text).toContain(url);
    expect(email.html).toContain("contextgateway.sharecapsule.org");
    expect(email.html).toContain("&amp;x=1");
    expect(email.html).not.toContain('href="' + url + '"');
  });

  it("requires both Resend credentials and sender identity", () => {
    const base = {} as Env;
    expect(passwordResetEmailConfigured(base)).toBe(false);
    expect(passwordResetEmailConfigured({ ...base, RESEND_API_KEY: "re_test" })).toBe(false);
    expect(passwordResetEmailConfigured({ ...base, RESEND_API_KEY: "re_test", AUTH_EMAIL_FROM: "ContextGateway <security@sharecapsule.org>" })).toBe(true);
  });
});
