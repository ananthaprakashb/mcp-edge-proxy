export interface Policy {
  allowedMethods: string[];
  allowedNames: string[];
}

export interface PolicyEvaluation {
  allowed: boolean;
  reason: "missing_method" | "method_not_allowed" | "name_not_allowed" | "method_allowed_no_name" | "allowed_exact" | "allowed_wildcard";
  methodRule: string | null;
  nameRule: string | null;
}

function normalizeRules(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.length > 0);
}

export function parsePolicy(allowedMethodsJson: string, allowedNamesJson: string): Policy {
  let methods: unknown = [];
  let names: unknown = [];
  try {
    methods = JSON.parse(allowedMethodsJson);
  } catch {
    methods = [];
  }
  try {
    names = JSON.parse(allowedNamesJson);
  } catch {
    names = [];
  }
  return {
    allowedMethods: normalizeRules(methods),
    allowedNames: normalizeRules(names),
  };
}

function matchedRule(rules: string[], value: string): string | null {
  if (rules.includes(value)) return value;
  if (rules.includes("*")) return "*";
  return null;
}

export function evaluatePolicyDetailed(policy: Policy, method: string | null, name: string | null): PolicyEvaluation {
  if (!method) {
    return { allowed: false, reason: "missing_method", methodRule: null, nameRule: null };
  }
  const methodRule = matchedRule(policy.allowedMethods, method);
  if (!methodRule) {
    return { allowed: false, reason: "method_not_allowed", methodRule: null, nameRule: null };
  }
  if (name === null) {
    return { allowed: true, reason: "method_allowed_no_name", methodRule, nameRule: null };
  }
  const nameRule = matchedRule(policy.allowedNames, name);
  if (!nameRule) {
    return { allowed: false, reason: "name_not_allowed", methodRule, nameRule: null };
  }
  const wildcard = methodRule === "*" || nameRule === "*";
  return { allowed: true, reason: wildcard ? "allowed_wildcard" : "allowed_exact", methodRule, nameRule };
}

export function evaluatePolicy(policy: Policy, method: string | null, name: string | null): boolean {
  return evaluatePolicyDetailed(policy, method, name).allowed;
}

export function normalizePolicyInput(value: unknown, fallback: string[] = ["*"]): string[] {
  if (value === undefined) return fallback;
  const rules = normalizeRules(value);
  if (rules.length === 0) throw new Error("Policy rule arrays must contain at least one non-empty string");
  if (rules.some((rule) => rule !== "*" && rule.includes("*"))) {
    throw new Error("Only exact rule matches or the standalone '*' wildcard are supported");
  }
  return [...new Set(rules)];
}
