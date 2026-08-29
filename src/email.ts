import type { Env } from "./types";

const RESEND_EMAIL_ENDPOINT = "https://api.resend.com/emails";

function configured(value: string | undefined): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

export function passwordResetEmailConfigured(env: Env): boolean {
  return configured(env.RESEND_API_KEY) && configured(env.AUTH_EMAIL_FROM);
}

export function buildPasswordResetEmail(resetUrl: string): { subject: string; text: string; html: string } {
  const safeUrl = resetUrl.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  return {
    subject: "Reset your ContextGateway password",
    text: `A password reset was requested for your ContextGateway account. Open this link within 30 minutes: ${resetUrl}\n\nIf you did not request this, you can ignore this email.`,
    html: `<!doctype html><html><body style="font-family:Inter,Arial,sans-serif;background:#f6f7fb;color:#172033;padding:32px"><div style="max-width:560px;margin:auto;background:#fff;border:1px solid #e4e7ec;border-radius:16px;padding:32px"><p style="font-size:12px;font-weight:700;letter-spacing:.12em;color:#56657a">CONTEXTGATEWAY</p><h1 style="font-size:24px;margin:8px 0 12px">Reset your password</h1><p style="line-height:1.6">A password reset was requested for your ContextGateway account. This link expires in 30 minutes.</p><p style="margin:28px 0"><a href="${safeUrl}" style="display:inline-block;background:#172033;color:#fff;text-decoration:none;padding:12px 18px;border-radius:9px;font-weight:700">Reset password</a></p><p style="font-size:13px;line-height:1.6;color:#667085">If you did not request this change, you can ignore this email. Your password will remain unchanged.</p></div></body></html>`,
  };
}

export async function sendPasswordResetEmail(env: Env, to: string, resetUrl: string): Promise<void> {
  if (!passwordResetEmailConfigured(env)) throw new Error("password_reset_email_not_configured");

  const message = buildPasswordResetEmail(resetUrl);
  const response = await fetch(RESEND_EMAIL_ENDPOINT, {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: env.AUTH_EMAIL_FROM,
      to: [to],
      subject: message.subject,
      text: message.text,
      html: message.html,
    }),
  });

  if (!response.ok) throw new Error("password_reset_email_delivery_failed");
}
