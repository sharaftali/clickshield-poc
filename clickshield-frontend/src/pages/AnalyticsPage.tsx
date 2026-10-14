import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { analyticsApi } from "../services/p3Api";
import { Card, Loading, RangePicker, Topbar, pct } from "../components/ui";
import type { Breakdown, GroupBy, ReportRange } from "../types/api";

const RANGES = ["today", "7d", "30d"] as const;
const TABLE_DIMENSIONS: { key: GroupBy; label: string }[] = [
  { key: "campaign", label: "Campaign" }, { key: "country", label: "Country" }, { key: "device", label: "Device" },
  { key: "source", label: "Source" }, { key: "city", label: "City" }, { key: "asn", label: "ASN" }, { key: "isp", label: "ISP" },
];

function useBreakdown(groupBy: GroupBy, range: ReportRange) {
  return useQuery<Breakdown>({ queryKey: ["analytics", groupBy, range], queryFn: () => analyticsApi.fraud(groupBy, range) });
}

// Task 025 / spec §47: fraud by day, hour, campaign, country, city, ASN, ISP, device and source.
export default function AnalyticsPage() {
  const [range, setRange] = useState<ReportRange>("7d");
  const [dimension, setDimension] = useState<GroupBy>("campaign");
  const byDay = useBreakdown(range === "today" ? "hour" : "day", range);
  const byHour = useBreakdown("hour", range);
  const table = useBreakdown(dimension, range);

  const series = (byDay.data?.rows ?? []).map((r) => ({
    label: range === "today" ? `${r.key}:00` : r.key.slice(5),
    sessions: r.sessions, fraud: r.fraud, fraudRate: Math.round(r.fraud_rate * 1000) / 10,
  }));
  const hours = Array.from({ length: 24 }, (_, h) => {
    const row = byHour.data?.rows.find((r) => r.key === String(h));
    return { hour: `${h}`, sessions: row?.sessions ?? 0, fraud: row?.fraud ?? 0 };
  });

  return (
    <>
      <Topbar title="Fraud Analytics">
        <RangePicker value={range} options={RANGES} onChange={setRange} />
      </Topbar>
      <main className="page-body">
        <div className="page-header">
          <h1>Where fraud comes from</h1>
          <p>
            Fraud counts include your feedback: a session you marked legitimate leaves the fraud count. Days and hours are in
            {" "}{byDay.data?.timezone ?? "your organization's timezone"} (change it in Settings).
          </p>
        </div>

        <Card title={range === "today" ? "Today by hour" : "By day"} subtitle="Sessions and fraud, with the fraud rate">
          <div style={{ height: 260, padding: "8px 16px 16px" }}>
            {byDay.isLoading ? <Loading /> : (
              <ResponsiveContainer>
                <LineChart data={series}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                  <XAxis dataKey="label" fontSize={11} />
                  <YAxis yAxisId="count" fontSize={11} allowDecimals={false} />
                  <YAxis yAxisId="rate" orientation="right" fontSize={11} unit="%" />
                  <Tooltip />
                  <Legend />
                  <Line yAxisId="count" type="monotone" dataKey="sessions" name="Sessions" stroke="#2563eb" dot={false} />
                  <Line yAxisId="count" type="monotone" dataKey="fraud" name="Fraud" stroke="#dc2626" dot={false} />
                  <Line yAxisId="rate" type="monotone" dataKey="fraudRate" name="Fraud rate %" stroke="#b45309" strokeDasharray="4 3" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        <Card title="By hour of day" subtitle="When fraudulent clicks arrive">
          <div style={{ height: 220, padding: "8px 16px 16px" }}>
            <ResponsiveContainer>
              <BarChart data={hours}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis dataKey="hour" fontSize={11} />
                <YAxis fontSize={11} allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="sessions" name="Sessions" fill="#93c5fd" />
                <Bar dataKey="fraud" name="Fraud" fill="#dc2626" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card
          title="Breakdown"
          actions={
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {TABLE_DIMENSIONS.map((d) => (
                <button key={d.key} className={`btn btn-sm ${dimension === d.key ? "btn-primary" : "btn-secondary"}`} onClick={() => setDimension(d.key)}>
                  {d.label}
                </button>
              ))}
            </div>
          }
        >
          {table.isLoading ? <Loading /> : (
            <>
              {["campaign", "country", "device"].includes(dimension) && (table.data?.rows.length ?? 0) > 0 && (
                <div style={{ height: 200, padding: "8px 16px" }}>
                  <ResponsiveContainer>
                    <BarChart data={table.data!.rows.slice(0, 10)} layout="vertical" margin={{ left: 40 }}>
                      <XAxis type="number" fontSize={11} allowDecimals={false} />
                      <YAxis type="category" dataKey="label" fontSize={11} width={140} />
                      <Tooltip />
                      <Bar dataKey="sessions" name="Sessions" fill="#93c5fd" />
                      <Bar dataKey="fraud" name="Fraud" fill="#dc2626" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr><th>{TABLE_DIMENSIONS.find((d) => d.key === dimension)?.label}</th><th>Sessions</th><th>Paid clicks</th>
                      <th>Suspicious</th><th>Fraud</th><th>Fraud rate</th><th>Avg risk</th></tr>
                  </thead>
                  <tbody>
                    {(table.data?.rows ?? []).map((r) => (
                      <tr key={r.key}>
                        <td style={{ fontWeight: 550 }}>{r.label}</td><td>{r.sessions}</td><td>{r.clicks}</td><td>{r.suspicious}</td>
                        <td style={{ color: r.fraud ? "var(--red)" : undefined, fontWeight: 600 }}>{r.fraud}</td>
                        <td>{pct(r.fraud_rate)}</td><td>{r.avg_risk}</td>
                      </tr>
                    ))}
                    {!table.data?.rows.length && <tr><td colSpan={7} className="empty-state">No sessions in this period</td></tr>}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </Card>
      </main>
    </>
  );
}
