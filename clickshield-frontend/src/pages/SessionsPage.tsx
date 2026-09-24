import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { dashboardApi } from "../services/apiService";
import { verdictBadge, riskColor, fmtDate } from "../lib/utils";
import type { DashboardSessionSummary, Verdict } from "../types/api";

const VERDICT_FILTERS: Array<"ALL" | Verdict> = ["ALL", "SAFE", "MONITOR", "FLAG", "FRAUD"];

export default function SessionsPage() {
  const [limit, setLimit] = useState(50);
  const [selectedVerdict, setSelectedVerdict] = useState<"ALL" | Verdict>("ALL");
  const [search, setSearch] = useState("");

  const { data: sessions, isLoading, refetch, isFetching } = useQuery<DashboardSessionSummary[]>({
    queryKey: ["dashboard", "sessions", limit],
    queryFn: () => dashboardApi.sessions(limit),
  });

  const filteredSessions = useMemo(() => {
    if (!sessions) return [];
    return sessions.filter((s) => {
      const matchVerdict = selectedVerdict === "ALL" || s.verdict === selectedVerdict;
      const q = search.toLowerCase();
      const matchSearch =
        !q ||
        (s.ip_address && s.ip_address.toLowerCase().includes(q)) ||
        (s.device && s.device.toLowerCase().includes(q)) ||
        (s.browser && s.browser.toLowerCase().includes(q)) ||
        (s.landing_page && s.landing_page.toLowerCase().includes(q));
      return matchVerdict && matchSearch;
    });
  }, [sessions, selectedVerdict, search]);

  return (
    <>
      <header className="topbar">
        <h1 className="topbar-title">Visitor Sessions</h1>
        <div className="topbar-actions">
          <select
            className="form-input"
            style={{ width: "auto", padding: "5px 8px", fontSize: 13 }}
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
          >
            <option value={20}>20 sessions</option>
            <option value={50}>50 sessions</option>
            <option value={100}>100 sessions</option>
          </select>
          <button className="btn btn-secondary btn-sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshIcon size={13} />
            {isFetching ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </header>

      <main className="page-body">
        <div className="page-header">
          <h1>Tracked Traffic Sessions</h1>
          <p>Real-time analysis of click fingerprints, IP reputation, and behavioral anomaly scores.</p>
        </div>

        {/* Filter Bar */}
        <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 16, flexWrap: "wrap" }}>
          <div style={{ display: "flex", gap: 6 }}>
            {VERDICT_FILTERS.map((v) => (
              <button
                key={v}
                className={`btn btn-sm ${selectedVerdict === v ? "btn-primary" : "btn-secondary"}`}
                onClick={() => setSelectedVerdict(v)}
              >
                {v}
              </button>
            ))}
          </div>

          <div style={{ flex: 1, minWidth: 200, maxWidth: 360, marginLeft: "auto" }}>
            <input
              type="text"
              placeholder="Search by IP, device, browser, landing page..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="form-input"
              style={{ padding: "6px 12px", fontSize: 13 }}
            />
          </div>
        </div>

        {/* Table Card */}
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Verdict</th>
                  <th>Risk Score</th>
                  <th>IP Address</th>
                  <th>Device / Browser</th>
                  <th>Signals</th>
                  <th>Activity</th>
                  <th>Landing Page</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={8} className="empty-state">
                      <div className="spinner" />
                      <span>Loading sessions...</span>
                    </td>
                  </tr>
                ) : filteredSessions.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="empty-state">
                      No matching sessions found
                    </td>
                  </tr>
                ) : (
                  filteredSessions.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <span className={verdictBadge(s.verdict)}>{s.verdict}</span>
                      </td>
                      <td>
                        <div className="risk-bar-wrap">
                          <div className="risk-bar-bg" style={{ width: 64 }}>
                            <div
                              className="risk-bar-fill"
                              style={{
                                width: `${Math.min(s.risk_score, 100)}%`,
                                background: riskColor(s.risk_score),
                              }}
                            />
                          </div>
                          <span style={{ fontSize: 12, fontWeight: 600 }}>{s.risk_score}</span>
                          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>({s.confidence_score}%)</span>
                        </div>
                      </td>
                      <td className="text-mono" style={{ fontWeight: 550 }}>
                        {s.ip_address ?? "Unknown"}
                      </td>
                      <td style={{ fontSize: 12.5 }}>
                        <div>{s.device ?? "Unknown Device"}</div>
                        <div style={{ color: "var(--text-muted)", fontSize: 11 }}>{s.browser ?? "—"}</div>
                      </td>
                      <td>
                        <div style={{ display: "flex", gap: 4 }}>
                          {s.is_vpn && <span className="chip" style={{ color: "var(--amber)", background: "var(--amber-l)" }}>VPN</span>}
                          {s.is_proxy && <span className="chip" style={{ color: "var(--orange)", background: "var(--orange-l)" }}>Proxy</span>}
                          {!s.is_vpn && !s.is_proxy && <span style={{ color: "var(--text-muted)", fontSize: 12 }}>—</span>}
                        </div>
                      </td>
                      <td style={{ fontSize: 12.5 }}>
                        <span>{s.page_count} views</span>
                        <span style={{ color: "var(--text-muted)", margin: "0 4px" }}>&bull;</span>
                        <span>{s.click_count} clicks</span>
                      </td>
                      <td style={{ fontSize: 12, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={s.landing_page ?? ""}>
                        {s.landing_page ?? "—"}
                      </td>
                      <td style={{ fontSize: 12, color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                        {fmtDate(s.created_at)}
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
