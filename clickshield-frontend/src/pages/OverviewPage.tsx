import { useState } from "react";
import type React from "react";
import { useQuery } from "@tanstack/react-query";
import { alertsApi } from "../services/p3Api";
import { RangePicker } from "../components/ui";
import { Link } from "react-router-dom";
import { dashboardApi } from "../services/apiService";
import { verdictBadge, riskColor, fmtDate, fmtNumber } from "../lib/utils";
import type {
  DashboardAnomaly,
  DashboardOverview,
  DashboardSessionSummary,
  DashboardFraudEvent,
  DashboardTopIP,
} from "../types/api";

const ANOMALY_LABELS: Record<DashboardAnomaly["metric"], string> = {
  ad_landings: "Click spike",
  median_click_interval: "Clicks unusually close together",
  ad_landings_drop: "Traffic stopped — tracking removed?",
};

export default function OverviewPage() {
  const [range, setRange] = useState<"today" | "7d" | "30d">("today");
  const { data: overview, isLoading: overviewLoading, refetch: refetchOverview } = useQuery<DashboardOverview>({
    queryKey: ["dashboard", "overview", range],
    queryFn: () => dashboardApi.overview(range),
    refetchInterval: 10000,
  });
  const { data: criticalAlerts } = useQuery({
    queryKey: ["alerts", "active"],
    queryFn: () => alertsApi.list("active"),
    refetchInterval: 30000,
  });
  const critical = (criticalAlerts?.items ?? []).filter((a) => a.severity === "critical" && a.status === "open");

  const { data: sessions, isLoading: sessionsLoading } = useQuery<DashboardSessionSummary[]>({
    queryKey: ["dashboard", "sessions", 6],
    queryFn: () => dashboardApi.sessions(6),
    refetchInterval: 10000,
  });

  const { data: fraudEvents, isLoading: fraudLoading } = useQuery<DashboardFraudEvent[]>({
    queryKey: ["dashboard", "fraudEvents", 6],
    queryFn: () => dashboardApi.fraudEvents(6),
    refetchInterval: 10000,
  });

  const { data: topIPs, isLoading: ipsLoading } = useQuery<DashboardTopIP[]>({
    queryKey: ["dashboard", "topIPs", 5],
    queryFn: () => dashboardApi.topIPs(5),
    refetchInterval: 10000,
  });

  const { data: anomalies } = useQuery<DashboardAnomaly[]>({
    queryKey: ["dashboard", "anomalies"],
    queryFn: () => dashboardApi.anomalies(24),
    refetchInterval: 60000,
  });

  const statItems = [
    {
      label: "Paid Clicks",
      value: overview ? fmtNumber(overview.clicks) : "—",
      sub: `${overview ? fmtNumber(overview.total_sessions) : "—"} sessions in total`,
    },
    {
      label: "Fraud Rate",
      value: overview ? `${(overview.fraud_rate * 100).toFixed(1)}%` : "—",
      sub: "Fraud sessions / all sessions",
    },
    {
      label: "Suspicious Traffic",
      value: overview ? fmtNumber(overview.suspicious_sessions) : "—",
      sub: "Monitor, flag or fraud",
    },
    {
      label: "Needs Review",
      value: overview ? fmtNumber(overview.review_sessions) : "—",
      sub: "FLAG sessions awaiting feedback",
      link: "/sessions",
    },
    {
      label: "Fraud Detected",
      value: overview ? fmtNumber(overview.fraud_sessions) : "—",
      sub: "Confirmed malicious clicks",
    },
    {
      label: "Protected / Blocked",
      value: overview ? fmtNumber(overview.protected_ips) : "—",
      sub: "IPs excluded in Google Ads now",
    },
    {
      label: "Connected",
      value: overview ? `${overview.connected_websites} · ${overview.connected_google_accounts} · ${overview.protected_campaigns}` : "—",
      sub: "Websites · Google accounts · protected campaigns",
    },
    {
      label: "Avg Risk Score",
      value: overview ? `${overview.average_risk_score}/100` : "—",
      sub: "Across all active sessions",
    },
    {
      label: "High Confidence",
      value: overview ? fmtNumber(overview.high_confidence_traffic) : "—",
      sub: "High accuracy signals",
    },
  ];

  return (
    <>
      <header className="topbar">
        <h1 className="topbar-title">Traffic &amp; Fraud Overview</h1>
        <div className="topbar-actions">
          <RangePicker value={range} options={["today", "7d", "30d"] as const} onChange={setRange} />
          <button className="btn btn-secondary btn-sm" onClick={() => refetchOverview()}>
            <RefreshIcon size={13} />
            Refresh
          </button>
        </div>
      </header>

      <main className="page-body">
        {/* Critical alerts (task 028), e.g. "Protection action failed" (spec §43) */}
        {critical.length > 0 && (
          <div className="alert alert-error" style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
            <span><strong>{critical[0].title}</strong> — {critical[0].message}
              {critical.length > 1 && ` (+${critical.length - 1} more)`}</span>
            <Link to="/alerts">View alerts</Link>
          </div>
        )}

        {/* Protection status (spec §46) */}
        {overview && (
          <div className={`alert ${overview.protection_status === "ACTIVE" ? "alert-success" : "alert-info"}`}>
            Protection: <strong>{overview.protection_status === "ACTIVE" ? "active" : "setup required"}</strong>
            {overview.protection_missing.length > 0 && (
              <> — still missing: {overview.protection_missing.map((m) => ({
                verified_website: <Link key={m} to="/websites">a verified website</Link>,
                google_connection: <Link key={m} to="/google">a Google Ads connection</Link>,
                protected_campaign: <Link key={m} to="/google">a protected campaign</Link>,
              }[m] ?? m)).reduce<React.ReactNode[]>((acc, el, i) => (i ? [...acc, ", ", el] : [el]), [])}</>
            )}
            <span style={{ float: "right", fontSize: 12, color: "var(--text-muted)" }}>Times in {overview.timezone}</span>
          </div>
        )}

        {/* Stat Cards Grid */}
        <section className="stats-grid">
          {statItems.map((stat, idx) => (
            <div key={idx} className="stat-card">
              <div className="stat-label">{stat.label}</div>
              <div className="stat-value">{overviewLoading ? "..." : stat.value}</div>
              <div className="stat-sub">
                {"link" in stat && stat.link ? <Link to={stat.link}>{stat.sub}</Link> : stat.sub}
              </div>
            </div>
          ))}
        </section>

        {/* Campaign traffic anomalies (last 24 hours) */}
        {anomalies && anomalies.length > 0 && (
          <div className="card section-gap">
            <div className="card-header">
              <div>
                <h2 className="card-title">Traffic Anomalies</h2>
                <div className="card-subtitle">
                  Campaign hours far outside their usual pattern (last 24 hours). Context for the fraud engine, never a
                  block on their own.
                </div>
              </div>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Level</th>
                    <th>Campaign</th>
                    <th>What</th>
                    <th>Observed</th>
                    <th>Usual</th>
                    <th>Hour</th>
                  </tr>
                </thead>
                <tbody>
                  {anomalies.map((a) => (
                    <tr key={a.id}>
                      <td>
                        <span className={a.level === "HIGH" ? "badge badge-fraud" : "badge badge-monitor"}>{a.level}</span>
                      </td>
                      <td style={{ fontSize: 12.5 }}>{a.campaign_name}</td>
                      <td style={{ fontSize: 12.5 }}>{ANOMALY_LABELS[a.metric] ?? a.metric}</td>
                      <td style={{ fontWeight: 600 }}>
                        {a.metric === "median_click_interval" ? `${a.observed}s apart` : `${a.observed} clicks`}
                      </td>
                      <td style={{ color: "var(--text-muted)" }}>
                        {a.metric === "median_click_interval" ? `${a.expected}s` : a.expected}
                      </td>
                      <td style={{ fontSize: 12, color: "var(--text-muted)", whiteSpace: "nowrap" }}>{fmtDate(a.window_start)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Two Column Section: Recent Sessions + Recent Fraud Events */}
        <div className="two-col section-gap">
          {/* Recent Sessions */}
          <div className="card">
            <div className="card-header">
              <div>
                <h2 className="card-title">Recent Sessions</h2>
                <div className="card-subtitle">Real-time incoming ad traffic</div>
              </div>
              <Link to="/sessions" className="btn btn-secondary btn-sm">
                View all &rarr;
              </Link>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Verdict</th>
                    <th>IP Address</th>
                    <th>Risk</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {sessionsLoading ? (
                    <tr>
                      <td colSpan={4} className="empty-state">
                        <div className="spinner" />
                        <span>Loading sessions...</span>
                      </td>
                    </tr>
                  ) : !sessions || sessions.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="empty-state">
                        No sessions recorded yet
                      </td>
                    </tr>
                  ) : (
                    sessions.map((s) => (
                      <tr key={s.id}>
                        <td>
                          <span className={verdictBadge(s.verdict)}>{s.verdict}</span>
                        </td>
                        <td className="text-mono"><Link to={`/sessions/${s.id}`}>{s.ip_address ?? "Unknown"}</Link></td>
                        <td>
                          <div className="risk-bar-wrap">
                            <div className="risk-bar-bg" style={{ width: 60 }}>
                              <div
                                className="risk-bar-fill"
                                style={{
                                  width: `${Math.min(s.risk_score, 100)}%`,
                                  background: riskColor(s.risk_score),
                                }}
                              />
                            </div>
                            <span style={{ fontSize: 12, fontWeight: 600 }}>{s.risk_score}</span>
                          </div>
                        </td>
                        <td style={{ fontSize: 12, color: "var(--text-muted)" }}>
                          {fmtDate(s.created_at)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Recent Fraud Events */}
          <div className="card">
            <div className="card-header">
              <div>
                <h2 className="card-title">Triggered Fraud Rules</h2>
                <div className="card-subtitle">Heuristic and pattern detections</div>
              </div>
              <Link to="/fraud-events" className="btn btn-secondary btn-sm">
                View all &rarr;
              </Link>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Reason</th>
                    <th>Score</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {fraudLoading ? (
                    <tr>
                      <td colSpan={4} className="empty-state">
                        <div className="spinner" />
                        <span>Loading fraud events...</span>
                      </td>
                    </tr>
                  ) : !fraudEvents || fraudEvents.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="empty-state">
                        No fraud events recorded yet
                      </td>
                    </tr>
                  ) : (
                    fraudEvents.map((e) => (
                      <tr key={e.id}>
                        <td>
                          <span className="badge badge-fraud">{e.rule_name}</span>
                        </td>
                        <td style={{ fontSize: 12.5, maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {e.reason_code}
                        </td>
                        <td style={{ fontWeight: 600, color: "var(--red)" }}>
                          +{e.score_contribution}
                        </td>
                        <td style={{ fontSize: 12, color: "var(--text-muted)" }}>
                          {fmtDate(e.created_at)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Top IP Reputation */}
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Top High-Risk IP Addresses</h2>
              <div className="card-subtitle">IPs generating suspicious or fraudulent traffic patterns</div>
            </div>
            <Link to="/top-ips" className="btn btn-secondary btn-sm">
              View all IPs &rarr;
            </Link>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Risk Score</th>
                  <th>Confidence</th>
                  <th>Total Sessions</th>
                  <th>Fraud Sessions</th>
                </tr>
              </thead>
              <tbody>
                {ipsLoading ? (
                  <tr>
                    <td colSpan={5} className="empty-state">
                      <div className="spinner" />
                      <span>Loading top IPs...</span>
                    </td>
                  </tr>
                ) : !topIPs || topIPs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="empty-state">
                      No high risk IPs identified yet
                    </td>
                  </tr>
                ) : (
                  topIPs.map((ip) => (
                    <tr key={ip.ip}>
                      <td className="text-mono" style={{ fontWeight: 600 }}>{ip.ip}</td>
                      <td>
                        <div className="risk-bar-wrap">
                          <div className="risk-bar-bg" style={{ width: 80 }}>
                            <div
                              className="risk-bar-fill"
                              style={{
                                width: `${Math.min(ip.risk_score, 100)}%`,
                                background: riskColor(ip.risk_score),
                              }}
                            />
                          </div>
                          <span style={{ fontSize: 12.5, fontWeight: 600 }}>{ip.risk_score}</span>
                        </div>
                      </td>
                      <td>{ip.confidence}%</td>
                      <td>{fmtNumber(ip.total_sessions)}</td>
                      <td style={{ fontWeight: 600, color: ip.fraud_sessions > 0 ? "var(--red)" : "inherit" }}>
                        {fmtNumber(ip.fraud_sessions)}
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
