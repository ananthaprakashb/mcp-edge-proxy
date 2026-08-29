export interface D1Result<T = unknown> {
  success: boolean;
  results?: T[];
  meta?: Record<string, unknown>;
}

export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<D1Result<T>>;
  run<T = unknown>(): Promise<D1Result<T>>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]>;
}

export interface RateLimit {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface TraceSpan {
  setAttribute(key: string, value: string | number | boolean | undefined): void;
}

export interface Tracing {
  enterSpan<T>(name: string, callback: (span: TraceSpan) => T | Promise<T>): T | Promise<T>;
}

export interface ExecutionContextLike {
  waitUntil(promise: Promise<unknown>): void;
  tracing?: Tracing;
}

export interface Env {
  DB: D1Database;
  FREE_RATE_LIMITER: RateLimit;
  PAID_RATE_LIMITER: RateLimit;
  CONTROL_PLANE_TOKEN: string;
  UPSTREAM_ENCRYPTION_KEY: string;
  UPSTREAM_ENCRYPTION_KEYRING?: string;
  BETTER_AUTH_SECRET: string;
  CAPABILITY_SIGNING_KEY: string;
  CAPABILITY_SIGNING_KEYRING?: string;
  BETTER_AUTH_URL?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  STRIPE_PRO_PRICE_ID?: string;
  STRIPE_TEAM_PRICE_ID?: string;
  ALLOW_INSECURE_UPSTREAMS?: string;
}

export type Plan = "free" | "pro" | "team";
export type SubscriptionStatus = "free" | "trialing" | "active" | "past_due" | "canceled";
export type ExecutionMode = "direct" | "capability_required";
export type TraceAuthMode = "agent_key" | "capability";
export type UpstreamConnectionMode = "public" | "cloudflare_access";

export interface AccountRow {
  id: string;
  name: string;
  plan: Plan;
  subscription_status: SubscriptionStatus;
  billing_customer_id: string | null;
  billing_subscription_id: string | null;
  billing_price_id: string | null;
  billing_period_end: string | null;
  billing_cancel_at_period_end: number;
}

export interface GatewayRow {
  id: string;
  account_id: string;
  name: string;
  upstream_url: string;
  upstream_headers_ciphertext: string | null;
  upstream_headers_iv: string | null;
  upstream_secret_version: number;
  credentials_rotated_at: string | null;
  connection_mode: UpstreamConnectionMode;
  enabled: number;
}

export interface ApiKeyAuthRow {
  key_id: string;
  account_id: string;
  gateway_id: string;
  allowed_methods: string;
  allowed_names: string;
  execution_mode: ExecutionMode;
  secret_version?: number;
  plan: Plan;
  subscription_status: SubscriptionStatus;
}

export interface TraceRecord {
  id: string;
  accountId: string;
  gatewayId: string;
  apiKeyId: string | null;
  requestId: string;
  mcpMethod: string | null;
  mcpName: string | null;
  decision: string;
  statusCode: number;
  durationMs: number;
  requestBytes: number | null;
  responseBytes: number | null;
  authMode?: TraceAuthMode | null;
  capabilityJti?: string | null;
  policyReason?: string | null;
  policyMethodRule?: string | null;
  policyNameRule?: string | null;
}
