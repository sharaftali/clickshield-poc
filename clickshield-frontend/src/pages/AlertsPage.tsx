import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { alertsApi } from "../services/p3Api";
import { useCan } from "../lib/permissions";
import { fmtDate } from "../lib/utils";
import { Card, Empty, Loading, Topbar } from "../components/ui";
import type { AlertItem } from "../types/api";

const FILTERS = ["active", "resolved"] as const;
const SEVERITY_BADGE: Record<string, string> = { critical: "badge badge-fraud", warning: "badge badge-monitor", info: "badge" };

// Spec §66 alert system (task 028).
export default function AlertsPage() {
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("active");
  const canManage = useCan("alerts:manage");
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["alerts", filter], queryFn: () => alertsApi.list(filter), refetchInterval: 30000 });
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["alerts"] });
    queryClient.invalidateQueries({ queryKey: ["alerts-summary"] });
  };
  const ack = useMutation({ mutationFn: alertsApi.acknowledge, onSuccess: refresh });
  const resolve = useMutation({ mutationFn: alertsApi.resolve, onSuccess: refresh });

  return (
    <>
      <Topbar title="Alerts">
        <div style={{ display: "flex", gap: 4 }}>
          {FILTERS.map((f) => (
            <button key={f} className={`btn btn-sm ${filter === f ? "btn-primary" : "btn-secondary"}`} onClick={() => setFilter(f)}>
              {f === "active" ? "Open" : "Resolved"}
            </button>
          ))}
        </div>
      </Topbar>
      <main className="page-body">
        <div className="page-header">
          <h1>Alerts</h1>
          <p>Failures, expired Google access, limits, spikes and tracking problems. Repeats of the same problem are counted
            on one alert; most clear by themselves when the condition goes away.</p>
        </div>
        {isLoading ? <Loading /> : !data?.items.length ? <Card><Empty>No {filter === "active" ? "open" : "resolved"} alerts.</Empty></Card> : (
          data.items.map((a: AlertItem) => (
            <Card
              key={a.id}
              title={a.title}
              subtitle={<span><span className={SEVERITY_BADGE[a.severity]}>{a.severity}</span> {a.type.replace(/_/g, " ").toLowerCase()} ·
                {" "}{a.occurrences} occurrence{a.occurrences === 1 ? "" : "s"} · last {fmtDate(a.last_seen_at)}
                {a.status === "acknowledged" && " · acknowledged"}</span>}
              actions={canManage && a.status !== "resolved" && (
                <div style={{ display: "flex", gap: 6 }}>
                  {a.status === "open" && <button className="btn btn-secondary btn-sm" onClick={() => ack.mutate(a.id)}>Acknowledge</button>}
                  <button className="btn btn-secondary btn-sm" onClick={() => resolve.mutate(a.id)}>Resolve</button>
                </div>
              )}
            >
              <div style={{ padding: "0 16px 14px", fontSize: 13 }}>
                {a.message}
                {a.notifications.length > 0 && (
                  <div style={{ fontSize: 11.5, color: "var(--text-muted)", marginTop: 6 }}>
                    Email: {a.notifications.map((n) => `${n.recipient} (${n.status}${n.error ? `: ${n.error}` : ""})`).join(", ")}
                  </div>
                )}
              </div>
            </Card>
          ))
        )}
      </main>
    </>
  );
}
