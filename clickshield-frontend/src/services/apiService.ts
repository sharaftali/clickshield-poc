import { api } from "../lib/api";
import type {
  AuthResponse,
  AuthenticatedUserResponse,
  DashboardFraudEvent,
  DashboardOverview,
  DashboardSessionSummary,
  DashboardTopIP,
  GoogleAccountOut,
  GoogleConnectionOut,
  SelectCustomerIn,
  LoginRequest,
  RegisterRequest,
  RefreshTokenRequest,
  TokenPair,
  OrganizationResponse,
  ProtectionExclusionResponse,
  ProtectionQueueSummary,
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
  overview: () =>
    api.get<DashboardOverview>("/dashboard/overview").then((r) => r.data),

  /** GET /api/v1/dashboard/sessions?limit=N */
  sessions: (limit = 20) =>
    api
      .get<DashboardSessionSummary[]>("/dashboard/sessions", { params: { limit } })
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
};

// ─── Protection ───────────────────────────────────────────────────────────────

export const protectionApi = {
  /** GET /api/v1/protection/exclusions */
  exclusions: () =>
    api
      .get<ProtectionExclusionResponse[]>("/protection/exclusions")
      .then((r) => r.data),

  /** POST /api/v1/protection/reconcile — run full queue sync with Google Ads */
  reconcile: () =>
    api.post<ProtectionQueueSummary>("/protection/reconcile").then((r) => r.data),

  /** POST /api/v1/protection/dry-run — evaluate candidates without submitting */
  dryRun: () =>
    api.post<{ queued: number }>("/protection/dry-run").then((r) => r.data),
};

// ─── Google Ads ───────────────────────────────────────────────────────────────

export const googleApi = {
  /** GET /api/v1/google/connections — list OAuth connections for org */
  connections: () =>
    api.get<GoogleConnectionOut[]>("/google/connections").then((r) => r.data),

  /** GET /api/v1/google/accounts — list accessible Google Ads customer accounts */
  accounts: () =>
    api.get<GoogleAccountOut[]>("/google/accounts").then((r) => r.data),

  /**
   * POST /api/v1/google/select-customer
   * After OAuth callback, persist which customer ID to use for exclusions.
   */
  selectCustomer: (body: SelectCustomerIn) =>
    api.post<GoogleConnectionOut>("/google/select-customer", body).then((r) => r.data),

  /**
   * GET /api/v1/google/connect
   * Starts the OAuth flow — must redirect the browser directly (not fetch).
   * Use: window.location.href = `http://127.0.0.1:8000/api/v1/google/connect`
   * (requires the user to be logged in via cookie or appended Bearer token)
   */
};
