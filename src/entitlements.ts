import type { Plan } from "./types";

export interface PlanEntitlements {
  plan: Plan;
  displayName: string;
  monthlyPriceUsd: number;
  gatewayLimit: number;
  activeKeyLimit: number;
  memberLimit: number;
  monthlyRequestLimit: number;
}

const ENTITLEMENTS: Record<Plan, PlanEntitlements> = {
  free: {
    plan: "free",
    displayName: "Free",
    monthlyPriceUsd: 0,
    gatewayLimit: 1,
    activeKeyLimit: 2,
    memberLimit: 1,
    monthlyRequestLimit: 10_000,
  },
  pro: {
    plan: "pro",
    displayName: "Pro",
    monthlyPriceUsd: 19,
    gatewayLimit: 10,
    activeKeyLimit: 25,
    memberLimit: 3,
    monthlyRequestLimit: 100_000,
  },
  team: {
    plan: "team",
    displayName: "Team",
    monthlyPriceUsd: 49,
    gatewayLimit: 50,
    activeKeyLimit: 100,
    memberLimit: 15,
    monthlyRequestLimit: 1_000_000,
  },
};

export function getPlanEntitlements(plan: Plan): PlanEntitlements {
  return ENTITLEMENTS[plan];
}

export function isPaidPlan(plan: Plan): plan is "pro" | "team" {
  return plan === "pro" || plan === "team";
}

export function allPlanEntitlements(): PlanEntitlements[] {
  return [ENTITLEMENTS.free, ENTITLEMENTS.pro, ENTITLEMENTS.team];
}
