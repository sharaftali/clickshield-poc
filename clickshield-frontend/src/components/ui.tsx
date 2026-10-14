import type { ReactNode } from "react";

export function Topbar({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <header className="topbar">
      <h1 className="topbar-title">{title}</h1>
      {children && <div className="topbar-actions">{children}</div>}
    </header>
  );
}

export function Card({ title, subtitle, actions, children }: { title?: string; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <div className="card section-gap">
      {(title || actions) && (
        <div className="card-header">
          <div>
            {title && <h2 className="card-title">{title}</h2>}
            {subtitle && <div className="card-subtitle">{subtitle}</div>}
          </div>
          {actions}
        </div>
      )}
      {children}
    </div>
  );
}

export function Loading({ label = "Loading..." }: { label?: string }) {
  return (
    <div className="empty-state">
      <div className="spinner" />
      <span>{label}</span>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty-state">{children}</div>;
}

export function RangePicker<T extends string>({ value, options, onChange }: { value: T; options: readonly T[]; onChange: (v: T) => void }) {
  const labels: Record<string, string> = { today: "Today", "7d": "7 days", "30d": "30 days" };
  return (
    <div style={{ display: "flex", gap: 4 }}>
      {options.map((option) => (
        <button key={option} className={`btn btn-sm ${value === option ? "btn-primary" : "btn-secondary"}`} onClick={() => onChange(option)}>
          {labels[option] ?? option}
        </button>
      ))}
    </div>
  );
}

export function errorText(error: unknown, fallback = "Something went wrong."): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => (d as { msg?: string }).msg ?? String(d)).join("; ");
  return fallback;
}

export function pct(rate: number): string {
  return `${(rate * 100).toFixed(rate > 0 && rate < 0.1 ? 1 : 0)}%`;
}

export function Field({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div style={{ display: "contents" }}>
      <div style={{ color: "var(--text-muted)", fontSize: 12 }}>{label}</div>
      <div style={{ fontSize: 13, wordBreak: "break-word" }}>{value ?? <span style={{ color: "var(--text-muted)" }}>Not available</span>}</div>
    </div>
  );
}

export function FieldGrid({ children }: { children: ReactNode }) {
  return <div style={{ display: "grid", gridTemplateColumns: "max-content 1fr", gap: "6px 16px", padding: 16 }}>{children}</div>;
}
