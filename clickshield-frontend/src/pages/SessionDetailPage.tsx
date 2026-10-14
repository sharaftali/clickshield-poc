import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { dashboardApi } from "../services/apiService";
import { sessionsApi } from "../services/p3Api";
import { bandLabel, exclusionBadge, fmtDate, riskColor, verdictBadge } from "../lib/utils";
import { useCan } from "../lib/permissions";
import { Card, Field, FieldGrid, Loading, Topbar, errorText } from "../components/ui";
import type { ClientVerdict, SessionDetail } from "../types/api";

const yes = (flag: boolean) => (flag ? <span className="badge badge-fraud">Yes</span> : "No");

// Spec §49 fraud event details and §33 explanation (task 026).
export default function SessionDetailPage() {
  const { id = "" } = useParams();
  const queryClient = useQueryClient();
  const canFeedback = useCan("sessions:feedback");
  const { data: s, isLoading, error } = useQuery<SessionDetail>({ queryKey: ["session", id], queryFn: () => sessionsApi.detail(id) });
  const feedback = useMutation({
    mutationFn: (verdict: ClientVerdict) => dashboardApi.setSessionFeedback(id, verdict),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["session", id] }),
  });

  if (isLoading) return (<><Topbar title="Session" /><main className="page-body"><Loading /></main></>);
  if (!s) return (<><Topbar title="Session" /><main className="page-body"><div className="alert alert-error">{errorText(error, "Session not found.")}</div></main></>);

  const location = [s.city, s.region, s.country].filter(Boolean).join(", ") || null;
  return (
    <>
      <Topbar title="Session detail" />
      <main className="page-body">
        <p><Link to="/sessions">&larr; Sessions</Link></p>

        <div className="card section-gap" style={{ padding: 16, display: "flex", gap: 24, alignItems: "center", flexWrap: "wrap" }}>
          <span className={verdictBadge(s.verdict)} style={{ fontSize: 14 }}>{s.verdict}</span>
          <div><div className="stat-label">Risk</div><div className="stat-value" style={{ color: riskColor(s.risk_score) }}>{s.risk_score}/100</div>
            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{bandLabel(s.risk_band)}</div></div>
          <div><div className="stat-label">Confidence</div><div className="stat-value">{s.confidence_score}%</div></div>
          <div><div className="stat-label">Signal types</div><div className="stat-value">{s.signal_diversity}</div></div>
          <div style={{ flex: 1, minWidth: 280, fontSize: 13 }}>{s.explanation}</div>
        </div>

        <div className="two-col section-gap">
          <Card title="Why" subtitle="Rules that fired, by contribution">
            <div className="table-wrap"><table>
              <thead><tr><th>Rule</th><th>Category</th><th>Risk</th><th>Confidence</th></tr></thead>
              <tbody>
                {s.reasons.map((r) => (
                  <tr key={r.code}>
                    <td><div style={{ fontWeight: 600, fontSize: 12.5 }}>{r.code}</div>
                      <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>{r.description}</div></td>
                    <td><span className="chip">{(r.category ?? "—").toLowerCase()}</span></td>
                    <td style={{ fontWeight: 700, color: "var(--red)" }}>+{r.contribution}</td>
                    <td>{r.confidence}%</td>
                  </tr>
                ))}
                {!s.reasons.length && <tr><td colSpan={4} className="empty-state">No rule fired</td></tr>}
              </tbody>
            </table></div>
          </Card>

          <Card title="Feedback" subtitle="Your label overrides the system verdict in reports and IP reputation (spec §50)">
            <FieldGrid>
              <Field label="System verdict" value={s.system_verdict} />
              <Field label="Your verdict" value={s.client_verdict ?? "Not given"} />
              <Field label="Final label" value={s.final_label ?? s.verdict} />
            </FieldGrid>
            {canFeedback && (
              <div style={{ display: "flex", gap: 8, padding: "0 16px 16px" }}>
                <button className={`btn btn-sm ${s.client_verdict === "fraud" ? "btn-primary" : "btn-secondary"}`}
                  onClick={() => feedback.mutate("fraud")} disabled={feedback.isPending}>Mark as fraud</button>
                <button className={`btn btn-sm ${s.client_verdict === "legitimate" ? "btn-primary" : "btn-secondary"}`}
                  onClick={() => feedback.mutate("legitimate")} disabled={feedback.isPending}>Mark as legitimate</button>
              </div>
            )}
          </Card>
        </div>

        <div className="two-col section-gap">
          <Card title="Source and campaign">
            <FieldGrid>
              <Field label="Source" value={s.source} />
              <Field label="Campaign" value={s.google_campaign_id
                ? <Link to={`/campaigns/${s.google_campaign_id}`}>{s.campaign_name} ({s.campaign_id})</Link> : null} />
              <Field label="Ad group" value={s.ad_group_id} />
              <Field label="Keyword" value={s.keyword ? `${s.keyword}${s.match_type ? ` (${s.match_type})` : ""}` : null} />
              <Field label="Google click ID" value={s.gclid_present ? "present" : null} />
              <Field label="UTM" value={[s.utm_source, s.utm_campaign].filter(Boolean).join(" / ") || null} />
              <Field label="Landing page" value={s.landing_page} />
              <Field label="Referrer" value={s.referrer} />
            </FieldGrid>
          </Card>
          <Card title="Network and device">
            <FieldGrid>
              <Field label="IP" value={<span className="text-mono">{s.ip_address}</span>} />
              <Field label="Location" value={location} />
              <Field label="Network" value={[s.asn, s.isp].filter(Boolean).join(" · ") || null} />
              <Field label="VPN / proxy / Tor" value={<>{yes(s.is_vpn)} / {yes(s.is_proxy)} / {yes(s.is_tor)}</>} />
              <Field label="Datacenter" value={yes(s.is_datacenter)} />
              <Field label="Device" value={[s.device, s.browser, s.os].filter(Boolean).join(" · ") || null} />
              <Field label="Language / timezone" value={[s.language, s.timezone].filter(Boolean).join(" · ") || null} />
            </FieldGrid>
          </Card>
        </div>

        <Card title="Behaviour">
          <FieldGrid>
            <Field label="Ad clicks (same IP or visitor)" value={`${s.clicks.clicks_60_seconds} in 60 s · ${s.clicks.clicks_5_minutes} in 5 min · ${s.clicks.clicks_24_hours} in 24 h`} />
            <Field label="Session duration" value={`${s.session_duration_seconds.toFixed(1)} s`} />
            <Field label="Pages / clicks / interactions" value={`${s.page_count} / ${s.click_count} / ${s.interaction_count}`} />
            <Field label="Scroll depth" value={`${Math.round(s.scroll_depth)}%`} />
          </FieldGrid>
        </Card>

        <Card title="Exclusion history" subtitle="Google Ads IP exclusions for this IP and campaign">
          {!s.exclusions.length ? <div className="empty-state">No exclusion for this IP</div> : s.exclusions.map((e) => (
            <div key={e.id} style={{ padding: "8px 16px 16px" }}>
              <div style={{ marginBottom: 6 }}>
                Campaign {e.campaign_id}: <span className={exclusionBadge(e.status)}>{e.status}</span>
                {e.api_request_id && <span className="text-mono" style={{ fontSize: 11, marginLeft: 8 }}>request {e.api_request_id}</span>}
                {e.last_error && <span style={{ color: "var(--red)", fontSize: 12, marginLeft: 8 }}>{e.last_error}</span>}
              </div>
              <ol style={{ margin: 0, paddingLeft: 18, fontSize: 12.5 }}>
                {e.timeline.map((t, i) => (
                  <li key={i}>{fmtDate(t.at)} — {t.action.replace(/_/g, " ").toLowerCase()} ({t.result})
                    {t.google_request_id && <span className="text-mono"> · {t.google_request_id}</span>}
                    {t.error && <span style={{ color: "var(--red)" }}> · {t.error}</span>}</li>
                ))}
              </ol>
            </div>
          ))}
        </Card>

        <Card title="Event timeline" subtitle={s.events_truncated ? "First 200 events" : `${s.events.length} events`}>
          <div className="table-wrap"><table>
            <thead><tr><th>Time</th><th>Event</th><th>Page</th></tr></thead>
            <tbody>{s.events.map((e, i) => (
              <tr key={i}>
                <td style={{ fontSize: 12, whiteSpace: "nowrap" }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
                <td><span className="chip">{e.event_type}</span></td>
                <td style={{ fontSize: 12, maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.page_url}</td>
              </tr>))}</tbody>
          </table></div>
        </Card>
      </main>
    </>
  );
}
