import { Link } from "react-router-dom";
import { useState, useMemo } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { dashboardApi } from "../services/apiService";
import { verdictBadge, riskColor, fmtDate, bandLabel, categoryList } from "../lib/utils";
import type { ClientVerdict, DashboardSessionSummary, Verdict } from "../types/api";

type SessionFilter = "ALL" | "REVIEW" | Verdict;
const VERDICT_FILTERS: SessionFilter[] = ["ALL", "REVIEW", "SAFE", "MONITOR", "FLAG", "FRAUD"];
const FILTER_LABELS: Partial<Record<SessionFilter, string>> = { REVIEW: "Needs review" };

export default function SessionsPage() {
  const [limit, setLimit] = useState(50);
  const [selectedVerdict, setSelectedVerdict] = useState<SessionFilter>("ALL");
  const [search, setSearch] = useState("");
  // "Needs review" = FLAG sessions without client feedback, fetched from the server so
  // older ones show up too (task 017). Other filters work on the loaded page.
  const review = selectedVerdict === "REVIEW";

  const { data: sessions, isLoading, refetch, isFetching } = useQuery<DashboardSessionSummary[]>({
    queryKey: ["dashboard", "sessions", limit, review],
    queryFn: () => dashboardApi.sessions(limit, review ? "FLAG" : undefined),
    refetchInterval: 10000,
  });

  const feedbackMutation = useMutation({
    mutationFn: ({ sessionId, clientVerdict }: { sessionId: string; clientVerdict: ClientVerdict }) =>
      dashboardApi.setSessionFeedback(sessionId, clientVerdict),
    onSuccess: () => {
      refetch();
    },
  });

  const filteredSessions = useMemo(() => {
    if (!sessions) return [];
    return sessions.filter((s) => {
      const matchVerdict =
        selectedVerdict === "ALL" ||
        (review ? s.client_verdict === null : s.verdict === selectedVerdict);
      const q = search.toLowerCase();
      const matchSearch =
        !q ||
        (s.ip_address && s.ip_address.toLowerCase().includes(q)) ||
        (s.device && s.device.toLowerCase().includes(q)) ||
        (s.browser && s.browser.toLowerCase().includes(q)) ||
        (s.landing_page && s.landing_page.toLowerCase().includes(q));
      return matchVerdict && matchSearch;
    });
  }, [sessions, selectedVerdict, review, search]);

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
          <p>
            Every session's risk, how sure the engine is, and how many independent kinds of evidence it rests on.
            FLAG sessions are never excluded automatically: review them and give feedback.
          </p>
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
                {FILTER_LABELS[v] ?? v}
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
                  <th>Feedback</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={9} className="empty-state">
                      <div className="spinner" />
                      <span>Loading sessions...</span>
                    </td>
                  </tr>
                ) : filteredSessions.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="empty-state">
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
                          <span style={{ fontSize: 11, color: "var(--text-muted)" }} title="Confidence in this verdict">
                            ({s.confidence_score}%)
                          </span>
                        </div>
                        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 3 }}>
                          {bandLabel(s.risk_band)} &bull;{" "}
                          <span title="Independent signal categories">
                            {s.signal_diversity} {s.signal_diversity === 1 ? "signal type" : "signal types"}
                          </span>
                        </div>
                        {categoryList(s.risk_categories).length > 0 && (
                          <div style={{ display: "flex", gap: 3, flexWrap: "wrap", marginTop: 3, maxWidth: 220 }}>
                            {categoryList(s.risk_categories).map(([category, points]) => (
                              <span key={category} className="chip" style={{ fontSize: 10 }} title={`${category}: +${points} risk`}>
                                {category.toLowerCase()} +{points}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="text-mono" style={{ fontWeight: 550 }}>
                        <Link to={`/sessions/${s.id}`} title="Open session detail">{s.ip_address ?? "Unknown"}</Link>
                      </td>
                      <td style={{ fontSize: 12.5 }}>
                        <div>{s.device ?? "Unknown Device"}</div>
                        <div style={{ color: "var(--text-muted)", fontSize: 11 }}>{s.browser ?? "—"}</div>
                      </td>
                      <td>
                        <div style={{ display: "flex", gap: 4 }}>
                          {s.is_vpn && <span className="chip" style={{ color: "var(--amber)", background: "var(--amber-l)" }}>VPN</span>}
                          {s.is_proxy && <span className="chip" style={{ color: "var(--orange)", background: "var(--orange-l)" }}>Proxy</span>}
                          {s.is_tor && <span className="chip" style={{ color: "var(--red)", background: "var(--red-soft)" }}>Tor</span>}
                          {s.is_datacenter && <span className="chip">Datacenter</span>}
                          {s.country && <span className="chip">{s.country}</span>}
                          {!s.is_vpn && !s.is_proxy && !s.is_tor && !s.is_datacenter && !s.country && (
                            <span style={{ color: "var(--text-muted)", fontSize: 12 }}>—</span>
                          )}
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
                      <td style={{ minWidth: 190 }}>
                        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                            <button
                              className={`btn btn-sm ${s.client_verdict === "legitimate" ? "btn-primary" : "btn-secondary"}`}
                              onClick={() => feedbackMutation.mutate({ sessionId: s.id, clientVerdict: "legitimate" })}
                              disabled={feedbackMutation.isPending}
                            >
                              Mark Legitimate
                            </button>
                            <button
                              className={`btn btn-sm ${s.client_verdict === "fraud" ? "btn-primary" : "btn-secondary"}`}
                              onClick={() => feedbackMutation.mutate({ sessionId: s.id, clientVerdict: "fraud" })}
                              disabled={feedbackMutation.isPending}
                            >
                              Mark Fraud
                            </button>
                          </div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                            Client feedback: {s.client_verdict ?? "Not provided"}
                          </div>
                        </div>
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
