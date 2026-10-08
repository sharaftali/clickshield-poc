import { Fragment, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { auditApi } from "../services/apiService";
import { fmtDate } from "../lib/utils";
import type { AuditLogEntry, AuditLogPage as AuditPage, AuditResult } from "../types/api";

const PAGE_SIZE = 50;

// Spec §44: every automated action (and security event) is recorded. Read-only.
export default function AuditLogPage() {
  const [action, setAction] = useState("");
  const [result, setResult] = useState<AuditResult | "">("");
  const [ip, setIp] = useState("");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  const query = {
    action: action || undefined,
    result: result || undefined,
    ip: ip.trim() || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  };

  const { data, isLoading, isFetching, refetch, error } = useQuery<AuditPage>({
    queryKey: ["audit", query],
    queryFn: () => auditApi.list(query),
    refetchInterval: 15000,
  });

  const { data: actions } = useQuery<string[]>({
    queryKey: ["audit", "actions"],
    queryFn: auditApi.actions,
  });

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const resetPage = () => setPage(0);

  return (
    <>
      <header className="topbar">
        <h1 className="topbar-title">Audit Log</h1>
        <div className="topbar-actions">
          <button className="btn btn-secondary btn-sm" onClick={() => refetch()} disabled={isFetching}>
            {isFetching ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </header>

      <main className="page-body">
        <div className="page-header">
          <h1>Audit Trail</h1>
          <p>Every Google Ads action, Google connection change, sign-in and feedback, with results and Google request IDs.</p>
        </div>

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 16 }}>
          <select
            className="form-input"
            style={{ width: "auto", minWidth: 220 }}
            value={action}
            onChange={(e) => { setAction(e.target.value); resetPage(); }}
          >
            <option value="">All actions</option>
            {(actions ?? []).map((name) => (
              <option key={name} value={name}>{name}</option>
            ))}
          </select>
          <select
            className="form-input"
            style={{ width: "auto" }}
            value={result}
            onChange={(e) => { setResult(e.target.value as AuditResult | ""); resetPage(); }}
          >
            <option value="">All results</option>
            <option value="SUCCESS">Success</option>
            <option value="FAILED">Failed</option>
            <option value="PENDING">Pending</option>
          </select>
          <input
            className="form-input"
            style={{ width: 200 }}
            placeholder="Filter by actor IP"
            value={ip}
            onChange={(e) => { setIp(e.target.value); resetPage(); }}
          />
        </div>

        {error && <div className="alert alert-error">Could not load the audit log.</div>}

        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Action</th>
                  <th>Result</th>
                  <th>Target</th>
                  <th>Actor IP</th>
                  <th>Google Request ID</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={6} className="empty-state">
                      <div className="spinner" />
                      <span>Loading audit log...</span>
                    </td>
                  </tr>
                ) : !data || data.items.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="empty-state">No audit entries match these filters.</td>
                  </tr>
                ) : (
                  data.items.map((entry) => (
                    <Fragment key={entry.id}>
                      <tr
                        onClick={() => setExpanded(expanded === entry.id ? null : entry.id)}
                        style={{ cursor: "pointer" }}
                        title="Show details"
                      >
                        <td style={{ fontSize: 12.5, whiteSpace: "nowrap" }}>{fmtDate(entry.created_at)}</td>
                        <td className="text-mono" style={{ fontSize: 12, fontWeight: 600 }}>{entry.action}</td>
                        <td><span className={resultBadge(entry.result)}>{entry.result}</span></td>
                        <td style={{ fontSize: 12.5 }}>{describeTarget(entry)}</td>
                        <td className="text-mono" style={{ fontSize: 12 }}>{entry.ip_address ?? "system"}</td>
                        <td className="text-mono" style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                          {entry.google_request_id ?? "—"}
                        </td>
                      </tr>
                      {expanded === entry.id && (
                        <tr>
                          <td colSpan={6} style={{ background: "var(--bg-subtle, #f8fafc)" }}>
                            {entry.error_message && (
                              <div style={{ color: "var(--danger, #b91c1c)", fontSize: 12.5, marginBottom: 6 }}>
                                {entry.error_message}
                              </div>
                            )}
                            <pre style={{ margin: 0, fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                              {JSON.stringify(entry.details ?? {}, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {data && data.total > PAGE_SIZE && (
          <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 12 }}>
            <button className="btn btn-secondary btn-sm" disabled={page === 0} onClick={() => setPage(page - 1)}>
              Previous
            </button>
            <span style={{ fontSize: 13 }}>
              Page {page + 1} of {totalPages} · {data.total} entries
            </span>
            <button className="btn btn-secondary btn-sm" disabled={page + 1 >= totalPages} onClick={() => setPage(page + 1)}>
              Next
            </button>
          </div>
        )}
      </main>
    </>
  );
}

function resultBadge(result: AuditResult): string {
  if (result === "SUCCESS") return "badge badge-active";
  if (result === "FAILED") return "badge badge-failed";
  return "badge badge-pending";
}

function describeTarget(entry: AuditLogEntry): string {
  const details = entry.details ?? {};
  const ip = details["ip"];
  const campaign = details["campaign_name"] ?? details["campaign_id"];
  const email = details["email"];
  if (ip && campaign) return `${ip} · campaign ${campaign}`;
  if (ip) return String(ip);
  if (campaign) return `campaign ${campaign}`;
  if (email) return String(email);
  return entry.resource_type ?? "—";
}
