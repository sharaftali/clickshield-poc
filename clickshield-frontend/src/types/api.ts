// ─── Auth ────────────────────────────────────────────────────────────────────

export type ProtectionMode = "STRICT" | "BALANCED" | "PASSIVE";
export type UserRole = "OWNER" | "ADMIN" | "MEMBER";

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  expires_in_minutes: number;
}

export interface UserPublic {
  id: string;
  organization_id: string;
  email: string;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
}

export interface OrganizationSummary {
  id: string;
  name: string;
  slug: string;
  protection_mode: ProtectionMode;
  is_active: boolean;
}

export interface AuthResponse {
  user: UserPublic;
  organization: OrganizationSummary;
  tokens: TokenPair;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  full_name: string;
  email: string;
  password: string;
  organization_name: string;
  organization_slug?: string;
  protection_mode?: ProtectionMode;
}

export interface RefreshTokenRequest {
  refresh_token: string;
}

export interface AuthenticatedUserResponse {
  user: UserPublic;
  organization: OrganizationSummary;
}

// ─── Dashboard ───────────────────────────────────────────────────────────────

export type Verdict = "SAFE" | "MONITOR" | "FLAG" | "FRAUD";

export interface DashboardOverview {
  total_sessions: number;
  suspicious_sessions: number;
  fraud_sessions: number;
  protected_ips: number;
  average_risk_score: number;
  high_confidence_traffic: number;
}

export interface DashboardSessionSummary {
  id: string;
  created_at: string;
  verdict: Verdict;
  risk_score: number;
  confidence_score: number;
  ip_address: string | null;
  device: string | null;
  browser: string | null;
  landing_page: string | null;
  page_count: number;
  click_count: number;
  is_vpn: boolean;
  is_proxy: boolean;
}

export interface DashboardFraudEvent {
  id: string;
  session_id: string;
  rule_name: string;
  reason_code: string;
  reason_text: string | null;
  score_contribution: number;
  rule_confidence: number;
  triggered: boolean;
  created_at: string;
}

export interface DashboardTopIP {
  ip: string;
  risk_score: number;
  confidence: number;
  total_sessions: number;
  fraud_sessions: number;
}

// ─── Protection ──────────────────────────────────────────────────────────────

export type ExclusionStatus = "PENDING" | "SUBMITTED" | "ACTIVE" | "FAILED" | "REMOVED";

export interface ProtectionExclusionResponse {
  id: string;
  organization_id: string;
  google_customer_id: string;
  campaign_id: string;
  google_campaign_id: string | null;
  ip_address: string;
  reason: string | null;
  risk_score: number;
  confidence: number;
  status: ExclusionStatus;
  google_resource_name: string | null;
  api_request_id: string | null;
}

export interface ProtectionQueueSummary {
  queued: number;
  processed: number;
  successful: number;
  failed: number;
  skipped: number;
}

// ─── Google ───────────────────────────────────────────────────────────────────

export interface GoogleConnectionOut {
  id: string;
  customer_id: string;
  login_customer_id: string | null;
  google_account_email: string | null;
  is_active: boolean;
}

export interface GoogleAccountOut {
  customer_id: string;
  descriptive_name: string | null;
  is_manager: boolean;
  is_test_account: boolean;
  currency_code: string | null;
  time_zone: string | null;
}

export interface SelectCustomerIn {
  customer_id: string;
  login_customer_id?: string | null;
  google_account_email?: string | null;
}

// ─── Organization ─────────────────────────────────────────────────────────────

export interface OrganizationResponse {
  id: string;
  name: string;
  slug: string;
  protection_mode: ProtectionMode;
  is_active: boolean;
}
