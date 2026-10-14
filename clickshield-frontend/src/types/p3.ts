// P3 API types: websites, analytics, campaigns, session detail, alerts, team, platform admin.
import type {
  ClientVerdict,
  ExclusionStatus,
  ProtectionExclusionResponse,
  RiskBand,
  RuleCategory,
  UserRole,
  Verdict,
} from "./api";

export interface Website {
  id: string;
  domain: string;
  display_name: string;
  tracking_token: string;
  is_verified: boolean;
  verified_at: string | null;
  verification_method: string | null;
  require_consent: boolean;
  enforce_origin: boolean;
  allowed_domains: string[];
  is_active: boolean;
  last_event_at: string | null;
  created_at: string;
  snippet: string;
}

export interface WebsiteVerifyResult {
  verified: boolean;
  method: string | null;
  detail: string;
  website: Website;
}

export type GroupBy = "day" | "hour" | "campaign" | "country" | "city" | "asn" | "isp" | "device" | "source";
export type ReportRange = "today" | "7d" | "30d";

export interface BreakdownRow {
  key: string;
  label: string;
  sessions: number;
  clicks: number;
  suspicious: number;
  fraud: number;
  fraud_rate: number;
  avg_risk: number;
}

export interface Breakdown {
  group_by: GroupBy;
  timezone: string;
  start: string;
  end: string;
  rows: BreakdownRow[];
}

export interface TrendPoint {
  day: string;
  sessions: number;
  fraud_rate: number;
  avg_risk: number;
}

export interface CampaignStats {
  id: string;
  campaign_id: string;
  name: string;
  status: string;
  campaign_type: string;
  protection_enabled: boolean;
  sessions: number;
  clicks: number;
  suspicious: number;
  fraud: number;
  fraud_rate: number;
  avg_risk: number;
  excluded_ips: number;
  exclusion_used: number;
  exclusion_limit: number;
  trend: TrendPoint[];
}

export interface CampaignDetail extends CampaignStats {
  recent_fraud_sessions: {
    id: string;
    created_at: string;
    ip_address: string | null;
    country: string | null;
    risk_score: number;
    confidence_score: number;
    verdict: Verdict;
    final_label: Verdict | null;
  }[];
  exclusions: ProtectionExclusionResponse[];
}

export interface SessionDetail {
  id: string;
  created_at: string;
  verdict: Verdict;
  system_verdict: Verdict;
  client_verdict: ClientVerdict | null;
  final_label: Verdict | null;
  risk_score: number;
  confidence_score: number;
  risk_band: RiskBand;
  signal_diversity: number;
  risk_categories: Partial<Record<RuleCategory, number>> | null;
  explanation: string;
  source: "paid" | "organic" | "direct";
  campaign_name: string | null;
  campaign_id: string | null;
  google_campaign_id: string | null;
  ad_group_id: string | null;
  keyword: string | null;
  match_type: string | null;
  gclid_present: boolean;
  utm_source: string | null;
  utm_campaign: string | null;
  ip_address: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  asn: string | null;
  isp: string | null;
  is_vpn: boolean;
  is_proxy: boolean;
  is_tor: boolean;
  is_datacenter: boolean;
  device: string | null;
  browser: string | null;
  os: string | null;
  language: string | null;
  timezone: string | null;
  landing_page: string | null;
  referrer: string | null;
  clicks: Record<string, number>;
  session_duration_seconds: number;
  page_count: number;
  click_count: number;
  interaction_count: number;
  scroll_depth: number;
  reasons: { code: string; category: RuleCategory | null; description: string | null; contribution: number; confidence: number }[];
  events: { event_type: string; page_url: string | null; timestamp: string; payload: Record<string, unknown> | null }[];
  events_truncated: boolean;
  exclusions: {
    id: string;
    campaign_id: string;
    status: ExclusionStatus;
    google_resource_name: string | null;
    api_request_id: string | null;
    last_error: string | null;
    created_at: string;
    timeline: { at: string; action: string; result: string; google_request_id: string | null; error: string | null }[];
  }[];
}

export type AlertSeverity = "info" | "warning" | "critical";
export type AlertStatus = "open" | "acknowledged" | "resolved";

export interface AlertItem {
  id: string;
  organization_id: string | null;
  type: string;
  severity: AlertSeverity;
  title: string;
  message: string;
  resource_type: string | null;
  resource_id: string | null;
  details: Record<string, unknown> | null;
  status: AlertStatus;
  occurrences: number;
  first_seen_at: string;
  last_seen_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  notifications: { channel: string; recipient: string; status: string; sent_at: string | null; error: string | null }[];
}

export interface AlertSummary {
  open: number;
  critical: number;
  warning: number;
}

export interface Member {
  id: string;
  email: string;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
  alert_emails: boolean;
  created_at: string;
}

export interface Invitation {
  id: string;
  email: string;
  role: UserRole;
  expires_at: string;
  accepted_at: string | null;
  revoked_at: string | null;
  created_at: string;
  invite_url?: string;
}

export interface InvitePreview {
  organization_name: string;
  email: string;
  role: UserRole;
}

export type HealthStatus = "HEALTHY" | "DEGRADED" | "DOWN" | "NOT_DEPLOYED";

export interface SystemHealth {
  status: HealthStatus;
  checked_at: string;
  components: { name: string; status: HealthStatus; detail: string; metrics: Record<string, unknown> }[];
}

export interface AdminOrganization {
  id: string;
  name: string;
  slug: string;
  protection_mode: string;
  is_active: boolean;
  created_at: string;
  users: number;
  websites: number;
  google_connections: number;
  sessions_24h: number;
  sessions_30d: number;
  fraud_30d: number;
}

export interface AdminConnection {
  id: string;
  organization_name: string;
  customer_id: string;
  google_account_email: string | null;
  is_active: boolean;
  needs_reauth: boolean;
  auth_error: string | null;
  last_refreshed_at: string | null;
}

export interface AdminAction {
  id: string;
  organization_name: string;
  action_type: string;
  status: string;
  attempts: number;
  max_attempts: number;
  last_error: string | null;
  ip_address: string | null;
  campaign_id: string | null;
  updated_at: string;
}

export interface AdminUser {
  id: string;
  email: string;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
  is_platform_admin: boolean;
  organization_name: string;
  created_at: string;
}
