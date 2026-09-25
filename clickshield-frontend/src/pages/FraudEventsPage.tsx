import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { dashboardApi } from "../services/apiService";
import { fmtDate } from "../lib/utils";
import type { DashboardFraudEvent } from "../types/api";

export default function FraudEventsPage() {
  const [limit, setLimit] = useState(50);
  const [search, setSearch] = useState("");

  const { data: events, isLoading, refetch, isFetching } = useQuery<DashboardFraudEvent[]>({
    queryKey: ["dashboard", "fraudEvents", limit],
    queryFn: () => dashboardApi.fraudEvents(limit),
    refetchInterval: 10000,
  });

  const filteredEvents = useMemo(() => {
    if (!events) return [];
    const q = search.toLowerCase();
    if (!q) return events;
    return events.filter(
      (e) =>
        e.rule_name.toLowerCase().includes(q) ||
        e.reason_code.toLowerCase().includes(q) ||
        (e.reason_text && e.reason_text.toLowerCase().includes(q)) ||
        e.session_id.toLowerCase().includes(q)
    );
  }, [events, search]);

  return (
    <>
      <header className="topbar">
        <h1 className="topbar-title">Fraud Events Log</h1>
        <div className="topbar-actions">
          <select
            className="form-input"
            style={{ width: "auto", padding: "5px 8px", fontSize: 13 }}
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
          >
            <option value={20}>20 events</option>
            <option value={50}>50 events</option>
            <option value={100}>100 events</option>
          </select>
          <button className="btn btn-secondary btn-sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshIcon size={13} />
            {isFetching ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </header>

      <main className="page-body">
        <div className="page-header">
          <h1>Detected Fraud Incidents</h1>
          <p>Rule execution triggers, heuristic anomaly weights, and fraud reasons identified by the detection engine.</p>
        </div>

        {/* Search */}
        <div style={{ marginBottom: 16, maxWidth: 380 }}>
          <input
            type="text"
            placeholder="Search by rule, reason code, or session ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="form-input"
            style={{ padding: "6px 12px", fontSize: 13 }}
          />
        </div>

        {/* Table Card */}
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule Name</th>
                  <th>Reason Code</th>
                  <th>Description</th>
                  <th>Score Impact</th>
                  <th>Confidence</th>
                  <th>Status</th>
                  <th>Session ID</th>
                  <th>Detected At</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={8} className="empty-state">
                      <div className="spinner" />
                      <span>Loading fraud events...</span>
                    </td>
                  </tr>
                ) : filteredEvents.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="empty-state">
                      No fraud events found
                    </td>
                  </tr>
                ) : (
                  filteredEvents.map((e) => (
                    <tr key={e.id}>
                      <td>
                        <span className="badge badge-fraud">{e.rule_name}</span>
                      </td>
                      <td style={{ fontWeight: 600, fontSize: 12.5 }}>{e.reason_code}</td>
                      <td style={{ fontSize: 12.5, color: "var(--text-secondary)", maxWidth: 220 }}>
                        {e.reason_text ?? "Rule condition threshold met"}
                      </td>
                      <td>
                        <span style={{ fontWeight: 700, color: "var(--red)", fontSize: 13 }}>
                          +{e.score_contribution}
                        </span>
                      </td>
                      <td style={{ fontSize: 12.5 }}>{e.rule_confidence}%</td>
                      <td>
                        {e.triggered ? (
                          <span className="badge badge-active">Triggered</span>
                        ) : (
                          <span className="badge badge-monitor">Suppressed</span>
                        )}
                      </td>
                      <td className="text-mono" style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                        {e.session_id.slice(0, 8)}...
                      </td>
                      <td style={{ fontSize: 12, color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                        {fmtDate(e.created_at)}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </>
  );
}

function RefreshIcon({ size }: { size: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 8A6 6 0 118 2c2 0 3.8.9 5 2.4" />
      <polyline points="14 2 14 5 11 5" />
    </svg>
  );
}
