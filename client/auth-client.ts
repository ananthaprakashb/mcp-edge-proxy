import { createAuthClient } from "better-auth/react";

const INVITE_SESSION_KEY = "contextgateway.pending-invite";
const baseAuthClient = createAuthClient();

function restoreInviteFragment(): void {
  if (typeof window === "undefined") return;
  const current = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  if (current.get("invite")) return;
  const stored = window.sessionStorage.getItem(INVITE_SESSION_KEY);
  if (!stored) return;
  current.set("invite", stored);
  const hash = current.toString();
  window.history.replaceState({}, "", `${window.location.pathname}${window.location.search}${hash ? `#${hash}` : ""}`);
  window.sessionStorage.removeItem(INVITE_SESSION_KEY);
}

restoreInviteFragment();

const originalSocial = baseAuthClient.signIn.social.bind(baseAuthClient.signIn);
const signIn = new Proxy(baseAuthClient.signIn, {
  get(target, property, receiver) {
    if (property !== "social") return Reflect.get(target, property, receiver);
    return async (...args: Parameters<typeof originalSocial>) => {
      const [input, ...rest] = args;
      if (typeof window !== "undefined" && input && typeof input.callbackURL === "string") {
        const separator = input.callbackURL.indexOf("#");
        if (separator >= 0) {
          const fragment = new URLSearchParams(input.callbackURL.slice(separator + 1));
          const invite = fragment.get("invite");
          if (invite) window.sessionStorage.setItem(INVITE_SESSION_KEY, invite);
          const callbackURL = input.callbackURL.slice(0, separator) || "/";
          return originalSocial({ ...input, callbackURL }, ...rest);
        }
      }
      return originalSocial(input, ...rest);
    };
  },
});

export const authClient = new Proxy(baseAuthClient, {
  get(target, property, receiver) {
    if (property === "signIn") return signIn;
    return Reflect.get(target, property, receiver);
  },
}) as typeof baseAuthClient;
