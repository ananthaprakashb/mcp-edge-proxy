export interface Policy {
  allowedMethods: string[];
  allowedNames: string[];
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

function matches(rules: string[], value: string): boolean {
  return rules.includes("*") || rules.includes(value);
}

export function evaluatePolicy(policy: Policy, method: string | null, name: string | null): boolean {
  if (!method || !matches(policy.allowedMethods, method)) return false;
  if (name === null) return true;
  return matches(policy.allowedNames, name);
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
