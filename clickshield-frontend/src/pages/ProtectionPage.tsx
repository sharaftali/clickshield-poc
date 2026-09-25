import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { protectionApi } from "../services/apiService";
import { exclusionBadge, riskColor } from "../lib/utils";
import type { ProtectionExclusionResponse, ProtectionQueueSummary } from "../types/api";

export default function ProtectionPage() {
  const [notification, setNotification] = useState<{ type: "success" | "error" | "info"; message: string } | null>(null);

  const { data: exclusions, isLoading, refetch, isFetching } = useQuery<ProtectionExclusionResponse[]>({
    queryKey: ["protection", "exclusions"],
    queryFn: protectionApi.exclusions,
    refetchInterval: 10000,
  });

  const dryRunMutation = useMutation({
    mutationFn: protectionApi.dryRun,
    onSuccess: (data) => {
      setNotification({
        type: "info",
        message: `Dry run completed successfully. ${data.queued} candidate IP(s) evaluated and queued for exclusion.`,
      });
      refetch();
    },
    onError: (err: any) => {
      setNotification({
        type: "error",
        message: err?.response?.data?.detail ?? "Failed to perform exclusion dry-run.",
      });
    },
  });

  const reconcileMutation = useMutation({
    mutationFn: protectionApi.reconcile,
    onSuccess: (data: ProtectionQueueSummary) => {
      setNotification({
        type: "success",
        message: `Queue reconciliation complete: ${data.processed} processed, ${data.successful} synced with Google Ads, ${data.failed} failed, ${data.skipped} skipped.`,
      });
      refetch();
    },
    onError: (err: any) => {
      setNotification({
        type: "error",
        message: err?.response?.data?.detail ?? "Failed to reconcile exclusion queue with Google Ads.",
      });
    },
  });

  const isBusy = dryRunMutation.isPending || reconcileMutation.isPending || isFetching;

  return (
    <>
      <header className="topbar">
        <h1 className="topbar-title">Google Ads Protection Engine</h1>
        <div className="topbar-actions">
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => dryRunMutation.mutate()}
            disabled={isBusy}
          >
            {dryRunMutation.isPending ? "Evaluating..." : "Run Dry-Run"}
          </button>
          <button
            className="btn btn-primary btn-sm"
            onClick={() => reconcileMutation.mutate()}
            disabled={isBusy}
          >
            {reconcileMutation.isPending ? "Syncing..." : "Reconcile Queue"}
          </button>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => refetch()}
            disabled={isBusy}
          >
            <RefreshIcon size={13} />
            Refresh
          </button>
        </div>
      </header>

      <main className="page-body">
        <div className="page-header">
          <h1>IP Exclusion Management</h1>
          <p>Automated IP blacklist synchronized directly with connected Google Ads campaign criteria.</p>
        </div>

        {notification && (
          <div className={`alert alert-${notification.type}`} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>{notification.message}</span>
            <button
              onClick={() => setNotification(null)}
              style={{ background: "none", border: "none", cursor: "pointer", fontWeight: 700, padding: "0 6px" }}
            >
              &times;
            </button>
          </div>
        )}

        {/* Protection Summary Cards */}
        <section className="stats-grid" style={{ marginBottom: 20 }}>
          <div className="stat-card">
            <div className="stat-label">Total Exclusions</div>
            <div className="stat-value">{exclusions ? exclusions.length : "—"}</div>
            <div className="stat-sub">Managed blacklist entries</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Active on Google Ads</div>
            <div className="stat-value">
              {exclusions ? exclusions.filter((e) => e.status === "ACTIVE").length : "—"}
            </div>
            <div className="stat-sub">Confirmed live blocking</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Pending Sync</div>
            <div className="stat-value">
              {exclusions ? exclusions.filter((e) => e.status === "PENDING" || e.status === "SUBMITTED").length : "—"}
            </div>
            <div className="stat-sub">Awaiting next reconcile pass</div>
          </div>
        </section>

        {/* Exclusions Table */}
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Current IP Exclusions</h2>
              <div className="card-subtitle">Detailed record of blocked addresses and API delivery logs</div>
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
                  <th>Customer ID</th>
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
                      No IP exclusions queued or active yet. Click <strong>Run Dry-Run</strong> to discover candidate IPs.
                    </td>
                  </tr>
                ) : (
                  exclusions.map((item) => (
                    <tr key={item.id}>
                      <td className="text-mono" style={{ fontWeight: 600 }}>{item.ip_address}</td>
                      <td>
                        <span className={exclusionBadge(item.status)}>{item.status}</span>
                      </td>
                      <td>
                        <div className="risk-bar-wrap">
                          <div className="risk-bar-bg" style={{ width: 60 }}>
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
                      <td style={{ fontSize: 12.5, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={item.reason ?? ""}>
                        {item.reason ?? "High risk score threshold"}
                      </td>
                      <td className="text-mono" style={{ fontSize: 12 }}>
                        {item.google_customer_id}
                      </td>
                      <td className="text-mono" style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                        {item.google_resource_name ? item.google_resource_name.slice(-20) : "Pending API sync"}
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
