import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { planForPriceId, verifyStripeSignature } from "../src/stripe";
import type { Env } from "../src/types";

function fakeEnv(): Env {
  return {
    DB: null as unknown as Env["DB"],
    FREE_RATE_LIMITER: null as unknown as Env["FREE_RATE_LIMITER"],
    PAID_RATE_LIMITER: null as unknown as Env["PAID_RATE_LIMITER"],
    CONTROL_PLANE_TOKEN: "control",
    UPSTREAM_ENCRYPTION_KEY: "encrypt",
    BETTER_AUTH_SECRET: "auth",
    STRIPE_PRO_PRICE_ID: "price_pro",
    STRIPE_TEAM_PRICE_ID: "price_team",
  };
}

describe("Stripe integration", () => {
  it("maps configured prices to paid plans", () => {
    const env = fakeEnv();
    expect(planForPriceId(env, "price_pro")).toBe("pro");
    expect(planForPriceId(env, "price_team")).toBe("team");
    expect(planForPriceId(env, "price_unknown")).toBeNull();
  });

  it("verifies a fresh Stripe v1 signature over the raw body", async () => {
    const secret = "whsec_test_secret";
    const timestamp = 1_800_000_000;
    const body = '{"id":"evt_123","type":"customer.subscription.updated"}';
    const signature = createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
    expect(await verifyStripeSignature(body, `t=${timestamp},v1=${signature}`, secret, timestamp * 1000)).toBe(true);
  });

  it("rejects stale or modified Stripe payloads", async () => {
    const secret = "whsec_test_secret";
    const timestamp = 1_800_000_000;
    const body = '{"id":"evt_123"}';
    const signature = createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
    expect(await verifyStripeSignature(`${body} `, `t=${timestamp},v1=${signature}`, secret, timestamp * 1000)).toBe(false);
    expect(await verifyStripeSignature(body, `t=${timestamp},v1=${signature}`, secret, (timestamp + 301) * 1000)).toBe(false);
  });
});
