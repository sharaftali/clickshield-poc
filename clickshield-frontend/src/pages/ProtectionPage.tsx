import { useQuery } from "@tanstack/react-query";
import { protectionApi } from "../services/apiService";
import { exclusionBadge, riskColor } from "../lib/utils";
import type { ProtectionAction, ProtectionExclusionResponse, ProtectionQueueStatus } from "../types/api";

// Exclusions are created automatically when a session is judged FRAUD and sent to
// Google Ads by the background worker. This page only reports on that pipeline.

export default function ProtectionPage() {
  const { data: exclusions, isLoading, refetch, isFetching } = useQuery<ProtectionExclusionResponse[]>({
    queryKey: ["protection", "exclusions"],
    queryFn: protectionApi.exclusions,
    refetchInterval: 10000,
  });

  const { data: queue, refetch: refetchQueue } = useQuery<ProtectionQueueStatus>({
    queryKey: ["protection", "queue"],
    queryFn: protectionApi.queue,
    refetchInterval: 5000,
  });

  const { data: actions, refetch: refetchActions } = useQuery<ProtectionAction[]>({
    queryKey: ["protection", "actions"],
    queryFn: () => protectionApi.actions(undefined, 15),
    refetchInterval: 10000,
  });

  const refreshAll = () => {
    refetch();
    refetchQueue();
    refetchActions();
  };

  return (
    <>
      <header className="topbar">
        <h1 className="topbar-title">Google Ads Protection Engine</h1>
        <div className="topbar-actions">
          <button className="btn btn-secondary btn-sm" onClick={refreshAll} disabled={isFetching}>
            <RefreshIcon size={13} />
            Refresh
          </button>
        </div>
      </header>

      <main className="page-body">
        <div className="page-header">
          <h1>IP Exclusion Management</h1>
          <p>
            High-confidence fraud is excluded from your Google Ads campaigns automatically. Failed calls are retried
            with backoff; campaigns at their IP exclusion limit keep the strongest exclusions.
          </p>
        </div>

        {queue && !queue.auto_protection_enabled && (
          <div className="alert alert-info">
            Automatic protection is turned off: fraud is detected and reported, but no IP exclusions are created.
          </div>
        )}
        {queue?.dry_run && (
          <div className="alert alert-info">
            Dry-run mode: the worker processes actions without calling Google Ads; exclusions are marked SKIPPED.
          </div>
        )}
        {queue && queue.failed > 0 && (
          <div className="alert alert-error">
            {queue.failed} protection action{queue.failed === 1 ? "" : "s"} failed. See the error on each exclusion
            below and the Audit Log for details.
          </div>
        )}

        <section className="stats-grid" style={{ marginBottom: 20 }}>
          <div className="stat-card">
            <div className="stat-label">Active on Google Ads</div>
            <div className="stat-value">{queue ? queue.active_exclusions : "—"}</div>
            <div className="stat-sub">Confirmed live exclusions</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">In Queue</div>
            <div className="stat-value">{queue ? queue.pending + queue.processing : "—"}</div>
            <div className="stat-sub">Waiting for the worker</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Retrying</div>
            <div className="stat-value">{queue ? queue.retrying : "—"}</div>
            <div className="stat-sub">Google errors, retried with backoff</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Waiting for Capacity</div>
            <div className="stat-value">{queue ? queue.overflow_exclusions : "—"}</div>
            <div className="stat-sub">Campaign IP exclusion limit reached</div>
          </div>
        </section>

        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-header">
            <div>
              <h2 className="card-title">Current IP Exclusions</h2>
              <div className="card-subtitle">Blocked addresses and their Google Ads delivery state</div>
            </div>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Status</th>
                  <th>Risk Score</th>
                  <th>Confidence</th>
                  <th>Reason</th>
                  <th>Campaign</th>
                  <th>Resource Name</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={7} className="empty-state">
                      <div className="spinner" />
                      <span>Loading exclusion records...</span>
                    </td>
                  </tr>
                ) : !exclusions || exclusions.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="empty-state">
                      No IP exclusions yet. They appear here automatically when high-confidence fraud is detected on a
                      protected campaign.
                    </td>
                  </tr>
                ) : (
                  exclusions.map((item) => (
                    <tr key={item.id}>
                      <td className="text-mono" style={{ fontWeight: 600 }}>{item.ip_address}</td>
                      <td>
                        <span className={exclusionBadge(item.status)} title={item.last_error ?? undefined}>
                          {item.overflow ? "QUEUED" : item.status}
                        </span>
                        {item.last_error && item.status !== "ACTIVE" && (
                          <div
                            style={{ fontSize: 11.5, color: "var(--text-muted)", maxWidth: 240, marginTop: 4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                            title={item.last_error}
                          >
                            {item.status === "FAILED" ? "Protection action failed: " : ""}
                            {item.last_error}
                          </div>
                        )}
                      </td>
                      <td>
                        <div className="risk-bar-wrap">
                          <div className="risk-bar-bg" style={{ width: 60 }}>
                            <div
                              className="risk-bar-fill"
                              style={{ width: `${Math.min(item.risk_score, 100)}%`, background: riskColor(item.risk_score) }}
                            />
                          </div>
                          <span style={{ fontSize: 12.5, fontWeight: 600 }}>{item.risk_score}</span>
                        </div>
                      </td>
                      <td style={{ fontSize: 13 }}>{item.confidence}%</td>
                      <td style={{ fontSize: 12.5, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={item.reason ?? ""}>
                        {item.reason ?? "High risk score threshold"}
                      </td>
                      <td className="text-mono" style={{ fontSize: 12 }}>
                        {item.campaign_id}
                      </td>
                      <td className="text-mono" style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                        {item.google_resource_name ? item.google_resource_name.slice(-20) : "—"}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Recent Google Ads Actions</h2>
              <div className="card-subtitle">What the protection worker sent to Google, with retries</div>
            </div>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Action</th>
                  <th>IP Address</th>
                  <th>Status</th>
                  <th>Attempts</th>
                  <th>Next Retry / Done</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {!actions || actions.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="empty-state">No protection actions yet.</td>
                  </tr>
                ) : (
                  actions.map((action) => (
                    <tr key={action.id}>
                      <td style={{ fontSize: 12.5 }}>{action.action_type === "REMOVE_IP_EXCLUSION" ? "Remove exclusion" : "Add exclusion"}</td>
                      <td className="text-mono">{action.ip_address ?? "—"}</td>
                      <td>
                        <span className={actionBadge(action.status)}>{action.status}</span>
                      </td>
                      <td style={{ fontSize: 13 }}>
                        {action.attempts}/{action.max_attempts}
                      </td>
                      <td style={{ fontSize: 12.5 }}>
                        {action.status === "RETRYING" && action.scheduled_at
                          ? new Date(action.scheduled_at).toLocaleTimeString()
                          : action.completed_at
                            ? new Date(action.completed_at).toLocaleTimeString()
                            : "—"}
                      </td>
                      <td
                        style={{ fontSize: 12, color: "var(--text-muted)", maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                        title={action.last_error ?? ""}
                      >
                        {action.last_error ?? "—"}
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

function actionBadge(status: ProtectionAction["status"]): string {
  switch (status) {
    case "SUCCESS":
      return "badge badge-active";
    case "FAILED":
      return "badge badge-failed";
    case "RETRYING":
    case "PROCESSING":
      return "badge badge-submitted";
    default:
      return "badge badge-pending";
  }
}

function RefreshIcon({ size }: { size: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 8A6 6 0 118 2c2 0 3.8.9 5 2.4" />
      <polyline points="14 2 14 5 11 5" />
    </svg>
  );
}
