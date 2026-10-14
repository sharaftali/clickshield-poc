import { api } from "../lib/api";
import type {
  AuthResponse,
  AuthenticatedUserResponse,
  DashboardAnomaly,
  DashboardFraudEvent,
  DashboardOverview,
  DashboardSessionSummary,
  DashboardTopIP,
  ClientVerdict,
  GoogleAccountOut,
  GoogleCampaignOut,
  GoogleConnectionOut,
  CampaignSyncSummary,
  SelectCustomerIn,
  LoginRequest,
  RegisterRequest,
  RefreshTokenRequest,
  TokenPair,
  OrganizationResponse,
  OrganizationUpdate,
  FraudRule,
  RuleUpdate,
  Verdict,
  ProtectionExclusionResponse,
  ProtectionQueueStatus,
  ProtectionAction,
  ActionStatus,
  AuditLogPage,
  AuditLogQuery,
} from "../types/api";

// ─── Auth ─────────────────────────────────────────────────────────────────────

export const authApi = {
  /** POST /api/v1/auth/login */
  login: (body: LoginRequest) =>
    api.post<AuthResponse>("/auth/login", body).then((r) => r.data),

  /** POST /api/v1/auth/register — creates new org + user, returns AuthResponse */
  register: (body: RegisterRequest) =>
    api.post<AuthResponse>("/auth/register", body).then((r) => r.data),

  /** POST /api/v1/auth/refresh — exchange refresh token for a new token pair */
  refresh: (body: RefreshTokenRequest) =>
    api.post<TokenPair>("/auth/refresh", body).then((r) => r.data),

  /** GET /api/v1/auth/me — returns current user + org */
  me: () =>
    api.get<AuthenticatedUserResponse>("/auth/me").then((r) => r.data),
};

// ─── Dashboard ────────────────────────────────────────────────────────────────

export const dashboardApi = {
  /** GET /api/v1/dashboard/overview */
  overview: (range: "today" | "7d" | "30d" = "today") =>
    api.get<DashboardOverview>("/dashboard/overview", { params: { range } }).then((r) => r.data),

  /** GET /api/v1/dashboard/sessions?limit=N&verdict=FLAG (verdict FLAG = review queue) */
  sessions: (limit = 20, verdict?: Verdict) =>
    api
      .get<DashboardSessionSummary[]>("/dashboard/sessions", { params: { limit, verdict } })
      .then((r) => r.data),

  /** GET /api/v1/dashboard/anomalies?hours=N — campaign traffic anomalies */
  anomalies: (hours = 24) =>
    api.get<DashboardAnomaly[]>("/dashboard/anomalies", { params: { hours } }).then((r) => r.data),

  /** PATCH /api/v1/dashboard/sessions/:id/feedback */
  setSessionFeedback: (sessionId: string, clientVerdict: ClientVerdict) =>
    api
      .patch<DashboardSessionSummary>(`/dashboard/sessions/${sessionId}/feedback`, {
        client_verdict: clientVerdict,
      })
      .then((r) => r.data),

  /** GET /api/v1/dashboard/fraud-events?limit=N */
  fraudEvents: (limit = 20) =>
    api
      .get<DashboardFraudEvent[]>("/dashboard/fraud-events", { params: { limit } })
      .then((r) => r.data),

  /** GET /api/v1/dashboard/top-ip-reputation?limit=N */
  topIPs: (limit = 10) =>
    api
      .get<DashboardTopIP[]>("/dashboard/top-ip-reputation", { params: { limit } })
      .then((r) => r.data),
};

// ─── Organization ─────────────────────────────────────────────────────────────

export const orgApi = {
  /** GET /api/v1/organizations/me */
  me: () =>
    api.get<OrganizationResponse>("/organizations/me").then((r) => r.data),

  /** PATCH /api/v1/organizations/me — protection mode / custom thresholds (owner, admin) */
  update: (body: OrganizationUpdate) =>
    api.patch<OrganizationResponse>("/organizations/me", body).then((r) => r.data),
};

// ─── Rules ────────────────────────────────────────────────────────────────────

export const rulesApi = {
  /** GET /api/v1/rules — effective rules for this organization */
  list: () => api.get<FraudRule[]>("/rules").then((r) => r.data),

  /** PATCH /api/v1/rules/:code — organization override (owner, admin) */
  update: (code: string, body: RuleUpdate) =>
    api.patch<FraudRule>(`/rules/${code}`, body).then((r) => r.data),

  /** DELETE /api/v1/rules/:code/override — back to the global values */
  reset: (code: string) => api.delete<FraudRule>(`/rules/${code}/override`).then((r) => r.data),
};

// ─── Protection ───────────────────────────────────────────────────────────────

export const protectionApi = {
  /** GET /api/v1/protection/exclusions */
  exclusions: () =>
    api
      .get<ProtectionExclusionResponse[]>("/protection/exclusions")
      .then((r) => r.data),

  /** GET /api/v1/protection/queue — counts for the automatic protection pipeline */
  queue: () =>
    api.get<ProtectionQueueStatus>("/protection/queue").then((r) => r.data),

  /** GET /api/v1/protection/actions?status=&limit= — recent Google Ads actions */
  actions: (status?: ActionStatus, limit = 20) =>
    api
      .get<ProtectionAction[]>("/protection/actions", { params: { status, limit } })
      .then((r) => r.data),
};

// ─── Audit log ────────────────────────────────────────────────────────────────

export const auditApi = {
  /** GET /api/v1/audit-logs — tenant-scoped, newest first */
  list: (query: AuditLogQuery = {}) =>
    api.get<AuditLogPage>("/audit-logs", { params: query }).then((r) => r.data),

  /** GET /api/v1/audit-logs/actions — action names present (filter options) */
  actions: () => api.get<string[]>("/audit-logs/actions").then((r) => r.data),
};

// ─── Google Ads ───────────────────────────────────────────────────────────────

export const googleApi = {
  /** GET /api/v1/google/connections — list OAuth connections for org */
  connections: () =>
    api.get<GoogleConnectionOut[]>("/google/connections").then((r) => r.data),

  /** POST /api/v1/google/connect — start OAuth (task 033); navigate to the returned URL */
  connect: () =>
    api.post<{ authorization_url: string }>("/google/connect").then((r) => r.data),

  /** GET /api/v1/google/accounts — list accessible Google Ads customer accounts */
  accounts: () =>
    api.get<GoogleAccountOut[]>("/google/accounts").then((r) => r.data),

  /**
   * POST /api/v1/google/select-customer
   * After OAuth callback, persist which customer ID to use for exclusions.
   */
  selectCustomer: (body: SelectCustomerIn) =>
    api.post<GoogleConnectionOut>("/google/select-customer", body).then((r) => r.data),

  /** GET /api/v1/google/campaigns — list synced campaigns for the selected customer */
  campaigns: () =>
    api.get<GoogleCampaignOut[]>("/google/campaigns").then((r) => r.data),

  /** POST /api/v1/google/campaigns/sync — sync campaigns from Google Ads */
  syncCampaigns: () =>
    api.post<CampaignSyncSummary>("/google/campaigns/sync").then((r) => r.data),

  /** PATCH /api/v1/google/campaigns/:id/protection — enable or disable protection */
  updateCampaignProtection: (campaignRowId: string, protectionEnabled: boolean) =>
    api
      .patch<GoogleCampaignOut>(`/google/campaigns/${campaignRowId}/protection`, {
        protection_enabled: protectionEnabled,
      })
      .then((r) => r.data),

  /**
   * GET /api/v1/google/connect
   * Starts the OAuth flow — must redirect the browser directly (not fetch).
   * Use: window.location.href = `http://127.0.0.1:8000/api/v1/google/connect`
   * (requires the user to be logged in via cookie or appended Bearer token)
   */
};
