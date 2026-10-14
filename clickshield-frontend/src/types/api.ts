// ─── Auth ────────────────────────────────────────────────────────────────────

export type ProtectionMode = "conservative" | "balanced" | "aggressive" | "custom";
export type UserRole = "owner" | "admin" | "member";
export type ClientVerdict = "fraud" | "legitimate";

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
  is_platform_admin?: boolean;
  alert_emails?: boolean;
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
export type RiskBand = "LOW" | "MODERATE" | "HIGH" | "VERY_HIGH";
export type RuleCategory = "NETWORK" | "REPUTATION" | "VELOCITY" | "BEHAVIOR" | "AUTOMATION" | "GEO" | "ANOMALY";

export interface DashboardOverview {
  range: "today" | "7d" | "30d";
  timezone: string;
  protection_status: "ACTIVE" | "SETUP_REQUIRED";
  protection_missing: string[];
  clicks: number;
  fraud_rate: number;
  connected_websites: number;
  connected_google_accounts: number;
  protected_campaigns: number;
  total_sessions: number;
  suspicious_sessions: number;
  fraud_sessions: number;
  review_sessions: number;
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
  risk_band: RiskBand;
  signal_diversity: number;
  risk_categories: Partial<Record<RuleCategory, number>> | null;
  scoring_version: number | null;
  ip_address: string | null;
  country: string | null;
  device: string | null;
  browser: string | null;
  landing_page: string | null;
  page_count: number;
  click_count: number;
  is_vpn: boolean;
  is_proxy: boolean;
  is_tor: boolean;
  is_datacenter: boolean;
  session_duration_seconds: number;
  clicks_60_seconds: number;
  ad_click_interval_cv: number | null;
  event_interval_min_ms: number | null;
  client_verdict: ClientVerdict | null;
  final_label: Verdict | null;
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
  category: RuleCategory | null;
  rule_version: number | null;
  created_at: string;
}

export interface DashboardAnomaly {
  id: string;
  campaign_name: string;
  campaign_id: string;
  window_start: string;
  window_end: string;
  metric: "ad_landings" | "median_click_interval" | "ad_landings_drop";
  observed: number;
  expected: number;
  score: number;
  level: "MEDIUM" | "HIGH";
}

export interface DashboardTopIP {
  ip: string;
  risk_score: number;
  confidence: number;
  total_sessions: number;
  fraud_sessions: number;
}

// ─── Protection ──────────────────────────────────────────────────────────────

export type ExclusionStatus = "PENDING" | "SUBMITTED" | "ACTIVE" | "FAILED" | "REMOVED" | "SKIPPED";

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
  last_error: string | null;
  overflow: boolean;
  last_fraud_at: string | null;
}

/** GET /protection/queue — read-only view of the automatic protection pipeline. */
export interface ProtectionQueueStatus {
  auto_protection_enabled: boolean;
  dry_run: boolean;
  pending: number;
  processing: number;
  retrying: number;
  failed: number;
  succeeded: number;
  active_exclusions: number;
  overflow_exclusions: number;
}

export type ActionStatus = "PENDING" | "PROCESSING" | "SUCCESS" | "FAILED" | "RETRYING";

export interface ProtectionAction {
  id: string;
  action_type: "ADD_IP_EXCLUSION" | "REMOVE_IP_EXCLUSION" | "ADD_AUDIENCE_EXCLUSION";
  status: ActionStatus;
  attempts: number;
  max_attempts: number;
  last_error: string | null;
  scheduled_at: string | null;
  completed_at: string | null;
  updated_at: string;
  ip_address: string | null;
  campaign_id: string | null;
}

// ─── Audit log ────────────────────────────────────────────────────────────────

export type AuditResult = "SUCCESS" | "FAILED" | "PENDING";

export interface AuditLogEntry {
  id: string;
  created_at: string;
  action: string;
  result: AuditResult;
  user_id: string | null;
  resource_type: string | null;
  resource_id: string | null;
  ip_address: string | null;
  details: Record<string, unknown> | null;
  error_message: string | null;
  google_request_id: string | null;
}

export interface AuditLogPage {
  items: AuditLogEntry[];
  total: number;
  limit: number;
  offset: number;
}

export interface AuditLogQuery {
  action?: string;
  result?: AuditResult;
  ip?: string;
  limit?: number;
  offset?: number;
}

// ─── Google ───────────────────────────────────────────────────────────────────

export interface GoogleConnectionOut {
  id: string;
  customer_id: string;
  login_customer_id: string | null;
  google_account_email: string | null;
  is_active: boolean;
  needs_reauth: boolean;
  auth_error: string | null;
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

export interface GoogleCampaignOut {
  id: string;
  campaign_id: string;
  name: string;
  campaign_type: string;
  status: string;
  protection_enabled: boolean;
  exclusion_count: number;
  external_exclusion_count: number;
  exclusion_used: number;
  exclusion_limit: number;
  supports_ip_exclusion: boolean;
  geo_target_type: string | null;
  locations: CampaignLocation[];
}

export interface CampaignLocation {
  country_code: string | null;
  region: string | null;
  name: string | null;
  target_type: string | null;
  negative: boolean;
}

export interface CampaignSyncSummary {
  synced: number;
  created: number;
  updated: number;
  removed: number;
}

// ─── Organization ─────────────────────────────────────────────────────────────

export interface ProtectionPolicy {
  mode: ProtectionMode;
  flag_risk: number;
  fraud_risk: number;
  fraud_confidence: number;
  min_diversity: number;
  auto_exclude: boolean;
}

export type ProtectionSettings = Omit<ProtectionPolicy, "mode">;

export interface OrganizationResponse {
  id: string;
  name: string;
  slug: string;
  protection_mode: ProtectionMode;
  is_active: boolean;
  protection_settings: ProtectionSettings | null;
  timezone: string;
  raw_events_retention_days: number | null;
  sessions_retention_days: number | null;
  fraud_session_retention_days: number | null;
  policy: ProtectionPolicy | null;
  mode_defaults: Record<string, ProtectionPolicy>;
}

export interface OrganizationUpdate {
  protection_mode?: ProtectionMode;
  protection_settings?: Partial<ProtectionSettings>;
  timezone?: string;
  raw_events_retention_days?: number | null;
  sessions_retention_days?: number | null;
  fraud_session_retention_days?: number | null;
}

export * from "./p3";

// ─── Rules ────────────────────────────────────────────────────────────────────

export type RuleParamValue = number | string | boolean | null | string[];

export interface FraudRule {
  code: string;
  name: string;
  description: string;
  category: RuleCategory;
  enabled: boolean;
  weight: number;
  confidence: number;
  params: Record<string, RuleParamValue>;
  version: number;
  defaults: { enabled: boolean; weight: number; params: Record<string, RuleParamValue> };
  override: { enabled: boolean | null; weight: number | null; params: Record<string, RuleParamValue> | null; version: number } | null;
}

export interface RuleUpdate {
  enabled?: boolean | null;
  weight?: number | null;
  params?: Record<string, RuleParamValue> | null;
}
