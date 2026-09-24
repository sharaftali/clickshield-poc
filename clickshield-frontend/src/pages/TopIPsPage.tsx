import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { dashboardApi } from "../services/apiService";
import { riskColor, fmtNumber } from "../lib/utils";
import type { DashboardTopIP } from "../types/api";

export default function TopIPsPage() {
  const [limit, setLimit] = useState(20);
  const [search, setSearch] = useState("");

  const { data: topIPs, isLoading, refetch, isFetching } = useQuery<DashboardTopIP[]>({
    queryKey: ["dashboard", "topIPs", limit],
    queryFn: () => dashboardApi.topIPs(limit),
  });

  const filteredIPs = useMemo(() => {
    if (!topIPs) return [];
    const q = search.toLowerCase();
    if (!q) return topIPs;
    return topIPs.filter((ip) => ip.ip.toLowerCase().includes(q));
  }, [topIPs, search]);

  return (
    <>
      <header className="topbar">
        <h1 className="topbar-title">Top IP Reputation</h1>
        <div className="topbar-actions">
          <select
            className="form-input"
            style={{ width: "auto", padding: "5px 8px", fontSize: 13 }}
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
          >
            <option value={10}>Top 10 IPs</option>
            <option value={20}>Top 20 IPs</option>
            <option value={50}>Top 50 IPs</option>
          </select>
          <button className="btn btn-secondary btn-sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshIcon size={13} />
            {isFetching ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </header>

      <main className="page-body">
        <div className="page-header">
          <h1>IP Threat Intelligence</h1>
          <p>Ranked IP addresses exhibiting high frequency, suspicious click behavior, or repeated fraud score violations.</p>
        </div>

        {/* Search */}
        <div style={{ marginBottom: 16, maxWidth: 320 }}>
          <input
            type="text"
            placeholder="Search IP address..."
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
                  <th>IP Address</th>
                  <th>Risk Score</th>
                  <th>Detection Confidence</th>
                  <th>Total Sessions</th>
                  <th>Fraud Sessions</th>
                  <th>Fraud Rate</th>
                  <th>Recommendation</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={7} className="empty-state">
                      <div className="spinner" />
                      <span>Loading top IPs...</span>
                    </td>
                  </tr>
                ) : filteredIPs.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="empty-state">
                      No matching IP records found
                    </td>
                  </tr>
                ) : (
                  filteredIPs.map((item) => {
                    const fraudRate = item.total_sessions > 0
                      ? Math.round((item.fraud_sessions / item.total_sessions) * 100)
                      : 0;

                    return (
                      <tr key={item.ip}>
                        <td className="text-mono" style={{ fontWeight: 600 }}>{item.ip}</td>
                        <td>
                          <div className="risk-bar-wrap">
                            <div className="risk-bar-bg" style={{ width: 80 }}>
                              <div
                                className="risk-bar-fill"
                                style={{
                                  width: `${Math.min(item.risk_score, 100)}%`,
                                  background: riskColor(item.risk_score),
                                }}
                              />
                            </div>
                            <span style={{ fontSize: 12.5, fontWeight: 600 }}>{item.risk_score}</span>
                          </div>
                        </td>
                        <td style={{ fontSize: 13 }}>{item.confidence}%</td>
                        <td style={{ fontSize: 13 }}>{fmtNumber(item.total_sessions)}</td>
                        <td style={{ fontSize: 13, fontWeight: 600, color: item.fraud_sessions > 0 ? "var(--red)" : "inherit" }}>
                          {fmtNumber(item.fraud_sessions)}
                        </td>
                        <td>
                          <span className={fraudRate >= 50 ? "badge badge-fraud" : fraudRate > 0 ? "badge badge-flag" : "badge badge-safe"}>
                            {fraudRate}%
                          </span>
                        </td>
                        <td>
                          {item.risk_score >= 80 ? (
                            <span className="badge badge-fraud">Block in Google Ads</span>
                          ) : item.risk_score >= 50 ? (
                            <span className="badge badge-monitor">Monitor closely</span>
                          ) : (
                            <span className="badge badge-safe">Normal traffic</span>
                          )}
                        </td>
                      </tr>
                    );
                  })
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
