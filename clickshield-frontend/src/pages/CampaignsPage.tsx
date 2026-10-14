import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { campaignsApi } from "../services/p3Api";
import { exclusionBadge, fmtDate, riskColor, verdictBadge } from "../lib/utils";
import { Card, Empty, Loading, RangePicker, Topbar, pct } from "../components/ui";
import type { CampaignDetail, CampaignStats, ReportRange, TrendPoint } from "../types/api";

const RANGES = ["today", "7d", "30d"] as const;

function Sparkline({ points }: { points: TrendPoint[] }) {
  return (
    <div style={{ width: 120, height: 32 }} title="Fraud rate, last 14 days">
      <ResponsiveContainer>
        <LineChart data={points.map((p) => ({ ...p, rate: p.fraud_rate * 100 }))}>
          <Line type="monotone" dataKey="rate" stroke="#dc2626" strokeWidth={1.5} dot={false} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

// Spec §48 campaign view (task 026).
export default function CampaignsPage() {
  const [range, setRange] = useState<ReportRange>("30d");
  const { data, isLoading } = useQuery<CampaignStats[]>({ queryKey: ["campaigns", range], queryFn: () => campaignsApi.list(range) });
  return (
    <>
      <Topbar title="Campaigns"><RangePicker value={range} options={RANGES} onChange={setRange} /></Topbar>
      <main className="page-body">
        <div className="page-header">
          <h1>Campaign statistics</h1>
          <p>Clicks, suspicious and fraudulent traffic per synced Google Ads campaign, and the IP exclusions in use.</p>
        </div>
        <Card>
          {isLoading ? <Loading /> : !data?.length ? <Empty>No campaigns yet: connect Google Ads and sync campaigns.</Empty> : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Campaign</th><th>Status</th><th>Clicks</th><th>Suspicious</th><th>Fraud</th><th>Fraud %</th>
                    <th>Excluded IPs</th><th>Risk trend (14d)</th></tr>
                </thead>
                <tbody>
                  {data.map((c) => (
                    <tr key={c.id}>
                      <td><Link to={`/campaigns/${c.id}`} style={{ fontWeight: 600 }}>{c.name}</Link>
                        <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{c.campaign_type} · {c.campaign_id}</div></td>
                      <td><span className={c.status === "ENABLED" ? "badge badge-active" : "badge badge-monitor"}>{c.status}</span>
                        {!c.protection_enabled && <div style={{ fontSize: 11, color: "var(--text-muted)" }}>protection off</div>}</td>
                      <td>{c.clicks}</td><td>{c.suspicious}</td>
                      <td style={{ color: c.fraud ? "var(--red)" : undefined, fontWeight: 600 }}>{c.fraud}</td>
                      <td>{pct(c.fraud_rate)}</td>
                      <td>{c.excluded_ips} <span style={{ color: "var(--text-muted)", fontSize: 11 }}>({c.exclusion_used}/{c.exclusion_limit} slots)</span></td>
                      <td><Sparkline points={c.trend} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </main>
    </>
  );
}

export function CampaignDetailPage() {
  const { id = "" } = useParams();
  const [range, setRange] = useState<ReportRange>("30d");
  const { data: c, isLoading } = useQuery<CampaignDetail>({ queryKey: ["campaign", id, range], queryFn: () => campaignsApi.get(id, range) });
  if (isLoading || !c) return (<><Topbar title="Campaign" /><main className="page-body"><Loading /></main></>);
  return (
    <>
      <Topbar title={c.name}><RangePicker value={range} options={RANGES} onChange={setRange} /></Topbar>
      <main className="page-body">
        <p><Link to="/campaigns">&larr; All campaigns</Link></p>
        <section className="stats-grid">
          {[["Clicks", c.clicks], ["Suspicious", c.suspicious], ["Fraud", c.fraud], ["Fraud rate", pct(c.fraud_rate)],
            ["Average risk", c.avg_risk], ["Excluded IPs", `${c.excluded_ips} (${c.exclusion_used}/${c.exclusion_limit})`]].map(([label, value]) => (
            <div key={String(label)} className="stat-card"><div className="stat-label">{label}</div><div className="stat-value">{value}</div></div>
          ))}
        </section>
        <Card title="Risk trend" subtitle="Daily average risk and fraud rate, last 14 days">
          <div style={{ height: 220, padding: "8px 16px 16px" }}>
            <ResponsiveContainer>
              <LineChart data={c.trend.map((p) => ({ ...p, rate: Math.round(p.fraud_rate * 1000) / 10, day: p.day.slice(5) }))}>
                <XAxis dataKey="day" fontSize={11} />
                <YAxis fontSize={11} />
                <Tooltip />
                <Line type="monotone" dataKey="avg_risk" name="Avg risk" stroke="#b45309" dot={false} />
                <Line type="monotone" dataKey="rate" name="Fraud rate %" stroke="#dc2626" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <div className="two-col section-gap">
          <Card title="Recent fraud sessions">
            {!c.recent_fraud_sessions.length ? <Empty>None in this period</Empty> : (
              <div className="table-wrap"><table>
                <thead><tr><th>Verdict</th><th>IP</th><th>Risk</th><th>When</th></tr></thead>
                <tbody>{c.recent_fraud_sessions.map((s) => (
                  <tr key={s.id}>
                    <td><span className={verdictBadge(s.final_label ?? s.verdict)}>{s.final_label ?? s.verdict}</span></td>
                    <td className="text-mono"><Link to={`/sessions/${s.id}`}>{s.ip_address ?? "?"}</Link> {s.country}</td>
                    <td style={{ color: riskColor(s.risk_score), fontWeight: 600 }}>{s.risk_score} <span style={{ color: "var(--text-muted)", fontWeight: 400 }}>({s.confidence_score}%)</span></td>
                    <td style={{ fontSize: 12 }}>{fmtDate(s.created_at)}</td>
                  </tr>))}</tbody>
              </table></div>
            )}
          </Card>
          <Card title="IP exclusions on this campaign">
            {!c.exclusions.length ? <Empty>No exclusions</Empty> : (
              <div className="table-wrap"><table>
                <thead><tr><th>IP</th><th>Status</th><th>Confidence</th><th>Google request</th></tr></thead>
                <tbody>{c.exclusions.map((e) => (
                  <tr key={e.id}>
                    <td className="text-mono">{e.ip_address}</td>
                    <td><span className={exclusionBadge(e.status)}>{e.overflow ? "QUEUED" : e.status}</span></td>
                    <td>{e.confidence}%</td>
                    <td className="text-mono" style={{ fontSize: 11 }}>{e.api_request_id ?? "—"}</td>
                  </tr>))}</tbody>
              </table></div>
            )}
          </Card>
        </div>
      </main>
    </>
  );
}
