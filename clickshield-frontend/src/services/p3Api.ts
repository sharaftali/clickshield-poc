import { api } from "../lib/api";
import type {
  AdminAction,
  AdminConnection,
  AdminOrganization,
  AdminUser,
  AlertItem,
  AlertSummary,
  AuditLogPage,
  AuthResponse,
  Breakdown,
  CampaignDetail,
  CampaignStats,
  FraudRule,
  GroupBy,
  Invitation,
  InvitePreview,
  Member,
  ReportRange,
  SessionDetail,
  SystemHealth,
  UserRole,
  Website,
  WebsiteVerifyResult,
} from "../types/api";

const data = <T,>(p: Promise<{ data: T }>) => p.then((r) => r.data);

export const websitesApi = {
  list: () => data(api.get<Website[]>("/websites")),
  get: (id: string) => data(api.get<Website>(`/websites/${id}`)),
  create: (body: { domain: string; display_name?: string; require_consent?: boolean }) =>
    data(api.post<Website>("/websites", body)),
  update: (id: string, body: Partial<Pick<Website, "display_name" | "require_consent" | "enforce_origin" | "allowed_domains">>) =>
    data(api.patch<Website>(`/websites/${id}`, body)),
  rotateToken: (id: string) => data(api.post<Website>(`/websites/${id}/rotate-token`)),
  verify: (id: string) => data(api.post<WebsiteVerifyResult>(`/websites/${id}/verify`)),
  remove: (id: string) => data(api.delete<Website>(`/websites/${id}`)),
};

export const analyticsApi = {
  fraud: (groupBy: GroupBy, range: ReportRange, campaignId?: string) =>
    data(api.get<Breakdown>("/analytics/fraud", { params: { group_by: groupBy, range, campaign_id: campaignId } })),
};

export const campaignsApi = {
  list: (range: ReportRange = "30d") => data(api.get<CampaignStats[]>("/campaigns", { params: { range } })),
  get: (id: string, range: ReportRange = "30d") => data(api.get<CampaignDetail>(`/campaigns/${id}`, { params: { range } })),
};

export const sessionsApi = {
  detail: (id: string) => data(api.get<SessionDetail>(`/dashboard/sessions/${id}`)),
};

export const alertsApi = {
  list: (status: "active" | "open" | "acknowledged" | "resolved" = "active") =>
    data(api.get<{ items: AlertItem[]; total: number }>("/alerts", { params: { status } })),
  summary: () => data(api.get<AlertSummary>("/alerts/summary")),
  acknowledge: (id: string) => data(api.post<AlertItem>(`/alerts/${id}/acknowledge`)),
  resolve: (id: string) => data(api.post<AlertItem>(`/alerts/${id}/resolve`)),
};

export const teamApi = {
  members: () => data(api.get<Member[]>("/users")),
  invitations: () => data(api.get<Invitation[]>("/users/invitations")),
  invite: (email: string, role: UserRole) => data(api.post<Invitation>("/users/invitations", { email, role })),
  revoke: (id: string) => data(api.delete<Invitation>(`/users/invitations/${id}`)),
  update: (id: string, body: { role?: UserRole; is_active?: boolean }) => data(api.patch<Member>(`/users/${id}`, body)),
  myPreferences: (alertEmails: boolean) => data(api.patch<Member>("/users/me", { alert_emails: alertEmails })),
  previewInvite: (token: string) => data(api.get<InvitePreview>(`/auth/invitations/${encodeURIComponent(token)}`)),
  acceptInvite: (token: string, fullName: string, password: string) =>
    data(api.post<AuthResponse>("/auth/accept-invite", { token, full_name: fullName, password })),
};

export const privacyApi = {
  erase: (body: { visitor_token?: string; ip?: string }) =>
    data(api.post<{ sessions_anonymized: number; events_deleted: number; visitors_deleted: number; reputation_rows_deleted: number }>(
      "/privacy/erase", body)),
};

export const adminApi = {
  health: () => data(api.get<SystemHealth>("/admin/health")),
  organizations: () => data(api.get<AdminOrganization[]>("/admin/organizations")),
  users: () => data(api.get<AdminUser[]>("/admin/users")),
  connections: () => data(api.get<AdminConnection[]>("/admin/connections")),
  failedActions: () => data(api.get<AdminAction[]>("/admin/actions", { params: { status: "FAILED" } })),
  retry: (id: string) => data(api.post<AdminAction>(`/admin/actions/${id}/retry`)),
  rules: () => data(api.get<FraudRule[]>("/admin/rules")),
  updateRule: (code: string, body: { enabled?: boolean; weight?: number; confidence?: number }) =>
    data(api.patch<FraudRule>(`/admin/rules/${code}`, body)),
  auditLogs: (params: { action?: string; organization_id?: string; limit?: number; offset?: number }) =>
    data(api.get<AuditLogPage>("/admin/audit-logs", { params })),
};
