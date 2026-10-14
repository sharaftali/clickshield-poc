import { useState, type ReactElement } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { adminApi } from "../services/p3Api";
import { fmtDate, fmtNumber } from "../lib/utils";
import { Card, Empty, Loading, Topbar, errorText } from "../components/ui";
import type { FraudRule, HealthStatus } from "../types/api";

const TABS = ["Health", "Organizations", "Users", "Connections", "Failed actions", "Rules", "Audit"] as const;
type Tab = (typeof TABS)[number];
const HEALTH_BADGE: Record<HealthStatus, string> = {
  HEALTHY: "badge badge-active", DEGRADED: "badge badge-monitor", DOWN: "badge badge-fraud", NOT_DEPLOYED: "badge",
};

// Platform administration for Click Shield staff (spec §64–65, task 027).
export default function AdminPage() {
  const [tab, setTab] = useState<Tab>("Health");
  return (
    <>
      <Topbar title="Platform admin" />
      <main className="page-body">
        <div style={{ display: "flex", gap: 4, marginBottom: 12, flexWrap: "wrap" }}>
          {TABS.map((t) => (
            <button key={t} className={`btn btn-sm ${tab === t ? "btn-primary" : "btn-secondary"}`} onClick={() => setTab(t)}>{t}</button>
          ))}
        </div>
        {tab === "Health" && <HealthTab />}
        {tab === "Organizations" && <OrganizationsTab />}
        {tab === "Users" && <UsersTab />}
        {tab === "Connections" && <ConnectionsTab />}
        {tab === "Failed actions" && <ActionsTab />}
        {tab === "Rules" && <RulesTab />}
        {tab === "Audit" && <AuditTab />}
        <p style={{ fontSize: 12, color: "var(--text-muted)" }}>ML models, subscriptions and usage billing: Phase 2.</p>
      </main>
    </>
  );
}

function HealthTab() {
  const { data, isLoading } = useQuery({ queryKey: ["admin", "health"], queryFn: adminApi.health, refetchInterval: 15000 });
  if (isLoading || !data) return <Loading />;
  return (
    <Card title="System health" subtitle={<>Overall <span className={HEALTH_BADGE[data.status]}>{data.status}</span> · checked {fmtDate(data.checked_at)} · refreshes every 15 s</>}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12, padding: 16 }}>
        {data.components.map((c) => (
          <div key={c.name} className="stat-card">
            <div className="stat-label" style={{ display: "flex", justifyContent: "space-between" }}>{c.name}
              <span className={HEALTH_BADGE[c.status]}>{c.status.replace("_", " ")}</span></div>
            <div style={{ fontSize: 12.5, marginTop: 6 }}>{c.detail}</div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
              {Object.entries(c.metrics).filter(([, v]) => v !== null).map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`).join(" · ")}
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function Table({ head, rows }: { head: string[]; rows: (string | number | null | undefined | ReactElement)[][] }) {
  if (!rows.length) return <Empty>Nothing here.</Empty>;
  return (
    <div className="table-wrap"><table>
      <thead><tr>{head.map((h) => <th key={h}>{h}</th>)}</tr></thead>
      <tbody>{rows.map((row, i) => <tr key={i}>{row.map((cell, j) => <td key={j} style={{ fontSize: 12.5 }}>{cell ?? "—"}</td>)}</tr>)}</tbody>
    </table></div>
  );
}

function OrganizationsTab() {
  const { data, isLoading } = useQuery({ queryKey: ["admin", "orgs"], queryFn: adminApi.organizations });
  if (isLoading || !data) return <Loading />;
  return <Card title={`Organizations (${data.length})`}><Table head={["Name", "Mode", "Users", "Websites", "Google", "Sessions 24h", "Sessions 30d", "Fraud 30d", "Created"]}
    rows={data.map((o) => [o.name, o.protection_mode, o.users, o.websites, o.google_connections, fmtNumber(o.sessions_24h), fmtNumber(o.sessions_30d), o.fraud_30d, fmtDate(o.created_at)])} /></Card>;
}

function UsersTab() {
  const { data, isLoading } = useQuery({ queryKey: ["admin", "users"], queryFn: adminApi.users });
  if (isLoading || !data) return <Loading />;
  return <Card title={`Users (${data.length})`}><Table head={["Email", "Name", "Organization", "Role", "Active", "Staff"]}
    rows={data.map((u) => [u.email, u.full_name, u.organization_name, u.role, u.is_active ? "yes" : "no", u.is_platform_admin ? "yes" : ""])} /></Card>;
}

function ConnectionsTab() {
  const { data, isLoading } = useQuery({ queryKey: ["admin", "connections"], queryFn: adminApi.connections });
  if (isLoading || !data) return <Loading />;
  return <Card title="Google connections" subtitle="Metadata only: credentials are never shown (spec §64).">
    <Table head={["Organization", "Customer", "Account", "Status", "Last refresh"]}
      rows={data.map((c) => [c.organization_name, c.customer_id || "not selected", c.google_account_email,
        c.needs_reauth ? <span className="badge badge-fraud" title={c.auth_error ?? ""}>needs re-auth</span> : c.is_active ? "active" : "inactive",
        c.last_refreshed_at ? fmtDate(c.last_refreshed_at) : null])} /></Card>;
}

function ActionsTab() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["admin", "actions"], queryFn: adminApi.failedActions });
  const retry = useMutation({ mutationFn: adminApi.retry, onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin", "actions"] }) });
  if (isLoading || !data) return <Loading />;
  return <Card title="Failed protection actions" subtitle="Retry re-queues the action (audited).">
    {retry.isError && <div className="alert alert-error" style={{ margin: 16 }}>{errorText(retry.error)}</div>}
    <Table head={["Organization", "Action", "IP", "Campaign", "Attempts", "Error", "Updated", ""]}
      rows={data.map((a) => [a.organization_name, a.action_type, a.ip_address, a.campaign_id, `${a.attempts}/${a.max_attempts}`,
        <span style={{ color: "var(--red)" }}>{a.last_error}</span>, fmtDate(a.updated_at),
        <button className="btn btn-secondary btn-sm" disabled={retry.isPending} onClick={() => retry.mutate(a.id)}>Retry</button>])} /></Card>;
}

function RulesTab() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery<FraudRule[]>({ queryKey: ["admin", "rules"], queryFn: adminApi.rules });
  const update = useMutation({
    mutationFn: ({ code, body }: { code: string; body: { enabled?: boolean; weight?: number; confidence?: number } }) => adminApi.updateRule(code, body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["admin", "rules"] }),
  });
  if (isLoading || !data) return <Loading />;
  return <Card title="Global rules" subtitle="Apply to every organization without an override. Each change bumps the rule version and is audited.">
    {update.isError && <div className="alert alert-error" style={{ margin: 16 }}>{errorText(update.error)}</div>}
    <Table head={["Rule", "Category", "On", "Weight", "Confidence", "Version"]}
      rows={data.map((r) => [<span title={r.description}>{r.code}</span>, r.category,
        <input type="checkbox" checked={r.enabled} onChange={(e) => update.mutate({ code: r.code, body: { enabled: e.target.checked } })} />,
        <input className="form-input" type="number" defaultValue={r.weight} style={{ width: 64, padding: "2px 6px" }}
          onBlur={(e) => Number(e.target.value) !== r.weight && update.mutate({ code: r.code, body: { weight: Number(e.target.value) } })} />,
        <input className="form-input" type="number" defaultValue={r.confidence} style={{ width: 64, padding: "2px 6px" }}
          onBlur={(e) => Number(e.target.value) !== r.confidence && update.mutate({ code: r.code, body: { confidence: Number(e.target.value) } })} />,
        r.version])} /></Card>;
}

function AuditTab() {
  const [action, setAction] = useState("");
  const { data, isLoading } = useQuery({ queryKey: ["admin", "audit", action], queryFn: () => adminApi.auditLogs({ action: action || undefined, limit: 100 }) });
  return <Card title="Audit log (all organizations)" actions={
    <input className="form-input" style={{ width: 240, padding: "4px 8px" }} placeholder="Filter by action, e.g. RULE_CHANGED"
      value={action} onChange={(e) => setAction(e.target.value.trim().toUpperCase())} />}>
    {isLoading || !data ? <Loading /> : <Table head={["When", "Action", "Result", "Resource", "Details"]}
      rows={data.items.map((a) => [fmtDate(a.created_at), a.action, a.result,
        `${a.resource_type ?? ""} ${a.resource_id ?? ""}`, <span className="text-mono" style={{ fontSize: 11 }}>{a.details ? JSON.stringify(a.details).slice(0, 140) : ""}</span>])} />}
  </Card>;
}
