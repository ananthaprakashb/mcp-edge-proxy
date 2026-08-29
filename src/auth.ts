import { betterAuth } from "better-auth";
import { passwordResetEmailConfigured, sendPasswordResetEmail } from "./email";
import type { Env } from "./types";

export function authProviderAvailability(env: Env): { github: boolean; google: boolean } {
  return {
    github: Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET),
    google: Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET),
  };
}

export function createAuth(env: Env, request: Request) {
  const baseURL = (env.BETTER_AUTH_URL || new URL(request.url).origin).replace(/\/$/, "");

  return betterAuth({
    database: env.DB as never,
    secret: env.BETTER_AUTH_SECRET,
    baseURL,
    basePath: "/api/auth",
    emailAndPassword: {
      enabled: true,
      minPasswordLength: 12,
      resetPasswordTokenExpiresIn: 30 * 60,
      revokeSessionsOnPasswordReset: true,
      sendResetPassword: async ({ user, url }) => {
        if (!passwordResetEmailConfigured(env)) {
          console.error("ContextGateway password reset email delivery is not configured");
          return;
        }
        const delivery = sendPasswordResetEmail(env, user.email, url).catch(() => {
          console.error("ContextGateway password reset email delivery failed");
        });
        void import("cloudflare:workers")
          .then(({ waitUntil }) => waitUntil(delivery))
          .catch(() => {
            void delivery;
          });
      },
    },
    socialProviders: {
      ...(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET
        ? {
            github: {
              clientId: env.GITHUB_CLIENT_ID,
              clientSecret: env.GITHUB_CLIENT_SECRET,
            },
          }
        : {}),
      ...(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET
        ? {
            google: {
              clientId: env.GOOGLE_CLIENT_ID,
              clientSecret: env.GOOGLE_CLIENT_SECRET,
            },
          }
        : {}),
    },
  });
}
