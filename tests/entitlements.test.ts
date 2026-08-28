import { describe, expect, it } from "vitest";
import { getPlanEntitlements } from "../src/entitlements";

 describe("plan entitlements", () => {
  it("keeps free intentionally constrained", () => {
    const free = getPlanEntitlements("free");
    expect(free.gatewayLimit).toBe(1);
    expect(free.activeKeyLimit).toBe(2);
    expect(free.monthlyRequestLimit).toBe(10_000);
  });

  it("increases capacity for paid plans", () => {
    const pro = getPlanEntitlements("pro");
    const team = getPlanEntitlements("team");
    expect(pro.monthlyPriceUsd).toBe(19);
    expect(team.monthlyPriceUsd).toBe(49);
    expect(team.gatewayLimit).toBeGreaterThan(pro.gatewayLimit);
    expect(team.activeKeyLimit).toBeGreaterThan(pro.activeKeyLimit);
    expect(team.monthlyRequestLimit).toBeGreaterThan(pro.monthlyRequestLimit);
  });
});
