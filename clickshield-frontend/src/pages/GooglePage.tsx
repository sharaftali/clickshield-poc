import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { googleApi } from "../services/apiService";
import { useAuthStore } from "../store/authStore";
import type { GoogleConnectionOut, GoogleAccountOut, SelectCustomerIn } from "../types/api";

export default function GooglePage() {
  const accessToken = useAuthStore((s) => s.accessToken);
  const [selectNotif, setSelectNotif] = useState<{ type: "success" | "error"; message: string } | null>(null);

  const {
    data: connections,
    isLoading: connLoading,
    refetch: refetchConn,
    isFetching: connFetching,
  } = useQuery<GoogleConnectionOut[]>({
    queryKey: ["google", "connections"],
    queryFn: googleApi.connections,
  });

  const {
    data: accounts,
    isLoading: accLoading,
    refetch: refetchAcc,
    isFetching: accFetching,
  } = useQuery<GoogleAccountOut[]>({
    queryKey: ["google", "accounts"],
    queryFn: googleApi.accounts,
  });

  const selectCustomerMutation = useMutation({
    mutationFn: (body: SelectCustomerIn) => googleApi.selectCustomer(body),
    onSuccess: () => {
      setSelectNotif({ type: "success", message: "Customer account selected and linked successfully." });
      refetchConn();
    },
    onError: (err: any) => {
      setSelectNotif({
        type: "error",
        message: err?.response?.data?.detail ?? "Failed to link customer account.",
      });
    },
  });

  const handleConnect = () => {
    // Redirect to backend OAuth endpoint — must carry Bearer token in a query param workaround
    // since browser navigations don't send Authorization headers.
    // The backend starts the OAuth flow as GET /api/v1/google/connect (requires auth).
    window.location.href = `http://127.0.0.1:8000/api/v1/google/connect?token=${accessToken ?? ""}`;
  };

  const handleSelectCustomer = (acc: GoogleAccountOut) => {
    const body: SelectCustomerIn = {
      customer_id: acc.customer_id,
      login_customer_id: null,
      google_account_email: acc.descriptive_name ?? null,
    };
    selectCustomerMutation.mutate(body);
  };

  const isBusy = connFetching || accFetching;

  return (
    <>
      <header className="topbar">
        <h1 className="topbar-title">Google Ads Integration</h1>
        <div className="topbar-actions">
          <button className="btn btn-primary btn-sm" onClick={handleConnect}>
            <GoogleIcon size={14} />
            Connect Google Ads
          </button>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => { refetchConn(); refetchAcc(); }}
            disabled={isBusy}
          >
            <RefreshIcon size={13} />
            Refresh
          </button>
        </div>
      </header>

      <main className="page-body">
        <div className="page-header">
          <h1>Connected Google Ads Accounts</h1>
          <p>
            Authorize ClickShield to synchronize campaign IP exclusions and prevent fraudulent clicks in real time.
          </p>
        </div>

        {selectNotif && (
          <div
            className={`alert alert-${selectNotif.type === "success" ? "success" : "error"}`}
            style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}
          >
            <span>{selectNotif.message}</span>
            <button
              onClick={() => setSelectNotif(null)}
              style={{ background: "none", border: "none", cursor: "pointer", fontWeight: 700, padding: "0 6px" }}
            >
              &times;
            </button>
          </div>
        )}

        {/* Info Banner */}
        <div className="alert alert-info" style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
          <div style={{ marginTop: 1 }}>
            <InfoIcon size={16} />
          </div>
          <div style={{ fontSize: 13, lineHeight: 1.5 }}>
            <strong>How it works:</strong> Click <em>Connect Google Ads</em> to authorize via OAuth. After connecting,
            select which Google Ads customer account should receive IP exclusions. ClickShield will then automatically
            block flagged IPs on your active campaigns.
          </div>
        </div>

        {/* Section 1: Active Connections */}
        <div className="card section-gap">
          <div className="card-header">
            <div>
              <h2 className="card-title">OAuth Connections</h2>
              <div className="card-subtitle">Active authorization tokens and linked manager credentials</div>
            </div>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Customer ID</th>
                  <th>Account Email</th>
                  <th>Manager / Login ID</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {connLoading ? (
                  <tr>
                    <td colSpan={4} className="empty-state">
                      <div className="spinner" />
                      <span>Loading connections...</span>
                    </td>
                  </tr>
                ) : !connections || connections.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="empty-state">
                      No active Google Ads connection. Click <strong>Connect Google Ads</strong> above.
                    </td>
                  </tr>
                ) : (
                  connections.map((c) => (
                    <tr key={c.id.toString()}>
                      <td className="text-mono" style={{ fontWeight: 600 }}>
                        {c.customer_id || <span style={{ color: "var(--text-muted)" }}>Not selected yet</span>}
                      </td>
                      <td>{c.google_account_email ?? "—"}</td>
                      <td className="text-mono">{c.login_customer_id ?? "Direct Account"}</td>
                      <td>
                        {c.is_active ? (
                          <span className="badge badge-active">Connected</span>
                        ) : (
                          <span className="badge badge-failed">Disconnected</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section 2: Accessible Accounts — with Select button */}
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Accessible Customer Accounts</h2>
              <div className="card-subtitle">
                Google Ads accounts available under your linked credentials. Click <strong>Use this account</strong> to
                link it as the exclusion target.
              </div>
            </div>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Account Name</th>
                  <th>Customer ID</th>
                  <th>Type</th>
                  <th>Currency</th>
                  <th>Timezone</th>
                  <th>Environment</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {accLoading ? (
                  <tr>
                    <td colSpan={7} className="empty-state">
                      <div className="spinner" />
                      <span>Loading accounts...</span>
                    </td>
                  </tr>
                ) : !accounts || accounts.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="empty-state">
                      No customer accounts discovered. Connect a Google account first.
                    </td>
                  </tr>
                ) : (
                  accounts.map((acc) => (
                    <tr key={acc.customer_id}>
                      <td style={{ fontWeight: 600 }}>{acc.descriptive_name ?? "Unnamed Account"}</td>
                      <td className="text-mono">{acc.customer_id}</td>
                      <td>
                        {acc.is_manager ? (
                          <span className="badge badge-monitor">MCC Manager</span>
                        ) : (
                          <span className="badge badge-submitted">Client Account</span>
                        )}
                      </td>
                      <td className="text-mono">{acc.currency_code ?? "USD"}</td>
                      <td style={{ fontSize: 12.5 }}>{acc.time_zone ?? "UTC"}</td>
                      <td>
                        {acc.is_test_account ? (
                          <span className="badge badge-monitor">Test</span>
                        ) : (
                          <span className="badge badge-safe">Production</span>
                        )}
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleSelectCustomer(acc)}
                          disabled={selectCustomerMutation.isPending}
                        >
                          {selectCustomerMutation.isPending ? "Linking..." : "Use this account"}
                        </button>
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

function GoogleIcon({ size }: { size: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none">
      <path d="M14 8.1c0-.5-.1-.9-.2-1.3H8v2.5h3.4a2.9 2.9 0 01-1.3 1.9v1.6h2.1C13.4 11.6 14 10 14 8.1z" fill="currentColor" />
      <path d="M8 14c1.7 0 3.1-.6 4.2-1.5l-2.1-1.6c-.6.4-1.3.6-2.1.6-1.6 0-3-1.1-3.5-2.5H2.4v1.6C3.5 12.7 5.6 14 8 14z" fill="currentColor" />
      <path d="M4.5 9c-.1-.4-.2-.8-.2-1.2S4.4 7 4.5 6.6V5H2.4A6 6 0 002 7.8c0 1 .2 2 .5 2.8L4.5 9z" fill="currentColor" />
      <path d="M8 3.8c.9 0 1.7.3 2.3.9l1.8-1.8C11.1 2 9.7 1.4 8 1.4 5.6 1.4 3.5 2.7 2.4 4.6L4.5 6.2C5 4.8 6.4 3.8 8 3.8z" fill="currentColor" />
    </svg>
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

function InfoIcon({ size }: { size: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="8" cy="8" r="6.5" />
      <line x1="8" y1="7" x2="8" y2="11" />
      <circle cx="8" cy="5" r="0.5" fill="currentColor" stroke="none" />
    </svg>
  );
}
