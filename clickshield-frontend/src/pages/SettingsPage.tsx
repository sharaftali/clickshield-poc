import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { orgApi, rulesApi } from "../services/apiService";
import { privacyApi } from "../services/p3Api";
import { useAuthStore } from "../store/authStore";
import type {
  FraudRule,
  OrganizationResponse,
  ProtectionMode,
  ProtectionSettings,
  RuleParamValue,
  RuleUpdate,
} from "../types/api";

const MODES: { mode: ProtectionMode; title: string; text: string }[] = [
  { mode: "conservative", title: "Conservative", text: "Block only with overwhelming, varied evidence. Fewest false positives." },
  { mode: "balanced", title: "Balanced", text: "Recommended. Blocks high-confidence fraud backed by several kinds of evidence." },
  { mode: "aggressive", title: "Aggressive", text: "Blocks earlier, with less evidence. More protection, more risk of blocking real visitors." },
  { mode: "custom", title: "Custom", text: "Set your own thresholds. One kind of signal can never block on its own." },
];

const THRESHOLDS: { key: keyof Omit<ProtectionSettings, "auto_exclude">; label: string; min: number; max: number; help: string }[] = [
  { key: "fraud_risk", label: "Block at risk ≥", min: 50, max: 100, help: "Risk score (0–100) needed for FRAUD" },
  { key: "fraud_confidence", label: "…with confidence ≥", min: 50, max: 100, help: "How sure the engine must be" },
  { key: "min_diversity", label: "…and signal types ≥", min: 2, max: 7, help: "Independent kinds of evidence (never below 2)" },
  { key: "flag_risk", label: "Flag for review at risk ≥", min: 30, max: 100, help: "High-risk sessions you review by hand" },
];

const CATEGORY_ORDER = ["NETWORK", "REPUTATION", "VELOCITY", "BEHAVIOR", "AUTOMATION", "GEO", "ANOMALY"];

function errorText(error: unknown): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => (d as { msg?: string }).msg ?? String(d)).join("; ");
  return "The change could not be saved.";
}

export default function SettingsPage() {
  const role = (useAuthStore((s) => s.user?.role) ?? "").toString().toLowerCase();
  const canEdit = role === "owner" || role === "admin";

  return (
    <>
      <header className="topbar">
        <h1 className="topbar-title">Detection Settings</h1>
      </header>
      <main className="page-body">
        <div className="page-header">
          <h1>Protection mode and rules</h1>
          <p>
            Changes apply to new traffic only. Existing verdicts and Google Ads exclusions are not changed. Every change
            is recorded in the audit log.
          </p>
        </div>
        {!canEdit && (
          <div className="alert alert-info" style={{ marginBottom: 16 }}>
            Only organization owners and admins can change these settings.
          </div>
        )}
        <ModeSection canEdit={canEdit} />
        <ReportingSection canEdit={canEdit} />
        <RulesSection canEdit={canEdit} />
        {role === "owner" && <PrivacySection />}
      </main>
    </>
  );
}

function ModeSection({ canEdit }: { canEdit: boolean }) {
  const queryClient = useQueryClient();
  const { data: org, isLoading } = useQuery<OrganizationResponse>({ queryKey: ["organization"], queryFn: orgApi.me });
  const [mode, setMode] = useState<ProtectionMode>("balanced");
  const [custom, setCustom] = useState<ProtectionSettings | null>(null);

  useEffect(() => {
    if (!org) return;
    setMode(org.protection_mode);
    setCustom(org.protection_settings ?? (org.policy ? { ...org.policy } : null));
  }, [org]);

  const save = useMutation({
    mutationFn: () =>
      orgApi.update({ protection_mode: mode, ...(mode === "custom" && custom ? { protection_settings: custom } : {}) }),
    onSuccess: (data) => queryClient.setQueryData(["organization"], data),
  });

  const shown = mode === "custom" ? custom : org?.mode_defaults?.[mode] ?? null;
  const dirty =
    !!org &&
    (mode !== org.protection_mode ||
      (mode === "custom" && JSON.stringify(custom) !== JSON.stringify(org.protection_settings)));

  return (
    <div className="card section-gap">
      <div className="card-header">
        <div>
          <h2 className="card-title">Protection mode</h2>
          <div className="card-subtitle">How much evidence is needed before an IP is excluded in Google Ads.</div>
        </div>
      </div>
      <div style={{ padding: 16 }}>
        {isLoading || !org ? (
          <div className="spinner" />
        ) : (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 10 }}>
              {MODES.map((m) => (
                <label
                  key={m.mode}
                  className="card"
                  style={{
                    padding: 12,
                    cursor: canEdit ? "pointer" : "default",
                    borderColor: mode === m.mode ? "var(--primary, #2563eb)" : undefined,
                    boxShadow: mode === m.mode ? "0 0 0 1px var(--primary, #2563eb)" : undefined,
                  }}
                >
                  <div style={{ display: "flex", gap: 8, alignItems: "center", fontWeight: 600 }}>
                    <input
                      type="radio"
                      name="mode"
                      checked={mode === m.mode}
                      disabled={!canEdit}
                      onChange={() => {
                        setMode(m.mode);
                        if (m.mode === "custom" && !custom && org.policy) setCustom({ ...org.policy });
                      }}
                    />
                    {m.title}
                    {org.protection_mode === m.mode && <span className="chip" style={{ fontSize: 10 }}>current</span>}
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 6 }}>{m.text}</div>
                </label>
              ))}
            </div>

            {shown && (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginTop: 16 }}>
                {THRESHOLDS.map((t) => (
                  <div key={t.key} className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label" title={t.help}>{t.label}</label>
                    <input
                      className="form-input"
                      type="number"
                      min={t.min}
                      max={t.max}
                      value={shown[t.key]}
                      disabled={!canEdit || mode !== "custom"}
                      onChange={(e) => custom && setCustom({ ...custom, [t.key]: Number(e.target.value) })}
                    />
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 3 }}>{t.help}</div>
                  </div>
                ))}
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label className="form-label">Exclude automatically</label>
                  <label style={{ display: "flex", gap: 6, alignItems: "center", fontSize: 13 }}>
                    <input
                      type="checkbox"
                      checked={shown.auto_exclude}
                      disabled={!canEdit || mode !== "custom"}
                      onChange={(e) => custom && setCustom({ ...custom, auto_exclude: e.target.checked })}
                    />
                    FRAUD verdicts create IP exclusions
                  </label>
                </div>
              </div>
            )}

            {save.isError && <div className="alert alert-error" style={{ marginTop: 12 }}>{errorText(save.error)}</div>}
            {save.isSuccess && !dirty && <div className="alert alert-success" style={{ marginTop: 12 }}>Saved.</div>}
            {canEdit && (
              <div style={{ marginTop: 14 }}>
                <button className="btn btn-primary btn-sm" disabled={!dirty || save.isPending} onClick={() => save.mutate()}>
                  {save.isPending ? "Saving..." : "Save protection mode"}
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function formatParam(value: RuleParamValue): string {
  if (Array.isArray(value)) return value.join(", ");
  if (value === null) return "";
  return String(value);
}

function parseParam(raw: string, original: RuleParamValue): RuleParamValue {
  if (Array.isArray(original)) return raw.split(",").map((v) => v.trim()).filter(Boolean);
  if (typeof original === "boolean") return raw === "true";
  if (raw.trim() === "") return null;
  if (typeof original === "number" || original === null) {
    const n = Number(raw);
    return Number.isNaN(n) ? raw : n;
  }
  return raw;
}

function RulesSection({ canEdit }: { canEdit: boolean }) {
  const { data: rules, isLoading } = useQuery<FraudRule[]>({ queryKey: ["rules"], queryFn: rulesApi.list });
  const grouped = useMemo(() => {
    const out = new Map<string, FraudRule[]>();
    for (const rule of rules ?? []) out.set(rule.category, [...(out.get(rule.category) ?? []), rule]);
    return CATEGORY_ORDER.filter((c) => out.has(c)).map((c) => [c, out.get(c)!] as const);
  }, [rules]);

  return (
    <div className="card section-gap">
      <div className="card-header">
        <div>
          <h2 className="card-title">Fraud rules</h2>
          <div className="card-subtitle">
            Weight = risk points at full strength. Rules in one category share diminishing returns, so they can't stack
            into a block on their own. Overrides apply to your organization only.
          </div>
        </div>
      </div>
      {isLoading ? (
        <div style={{ padding: 16 }}><div className="spinner" /></div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Rule</th>
                <th>On</th>
                <th>Weight</th>
                <th>Parameters</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {grouped.map(([category, list]) => (
                <RuleGroup key={category} category={category} rules={list} canEdit={canEdit} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function RuleGroup({ category, rules, canEdit }: { category: string; rules: FraudRule[]; canEdit: boolean }) {
  return (
    <>
      <tr>
        <td colSpan={5} style={{ background: "var(--bg-subtle, #f8fafc)", fontSize: 11, fontWeight: 700, letterSpacing: 0.4 }}>
          {category}
        </td>
      </tr>
      {rules.map((rule) => (
        <RuleRow key={rule.code} rule={rule} canEdit={canEdit} />
      ))}
    </>
  );
}

function RuleRow({ rule, canEdit }: { rule: FraudRule; canEdit: boolean }) {
  const queryClient = useQueryClient();
  const [weight, setWeight] = useState(String(rule.weight));
  const [params, setParams] = useState<Record<string, string>>(() =>
    Object.fromEntries(Object.entries(rule.params).map(([k, v]) => [k, formatParam(v)]))
  );

  useEffect(() => {
    setWeight(String(rule.weight));
    setParams(Object.fromEntries(Object.entries(rule.params).map(([k, v]) => [k, formatParam(v)])));
  }, [rule]);

  const replaceRule = (updated: FraudRule) =>
    queryClient.setQueryData<FraudRule[]>(["rules"], (old) => old?.map((r) => (r.code === updated.code ? updated : r)));
  const update = useMutation({ mutationFn: (body: RuleUpdate) => rulesApi.update(rule.code, body), onSuccess: replaceRule });
  const reset = useMutation({ mutationFn: () => rulesApi.reset(rule.code), onSuccess: replaceRule });

  const changedParams = Object.fromEntries(
    Object.entries(params)
      .filter(([k, v]) => v !== formatParam(rule.params[k]))
      .map(([k, v]) => [k, parseParam(v, rule.params[k])])
  );
  const dirty = Number(weight) !== rule.weight || Object.keys(changedParams).length > 0;
  const error = update.error ?? reset.error;

  return (
    <tr>
      <td style={{ maxWidth: 280 }}>
        <div style={{ fontWeight: 600, fontSize: 12.5 }}>{rule.name}</div>
        <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{rule.description}</div>
        <div style={{ fontSize: 10.5, color: "var(--text-muted)", marginTop: 2 }}>
          <span className="text-mono">{rule.code}</span> · v{rule.version}
          {rule.override && <span className="chip" style={{ fontSize: 10, marginLeft: 6 }}>customized</span>}
        </div>
        {error && <div style={{ color: "var(--red)", fontSize: 11, marginTop: 4 }}>{errorText(error)}</div>}
      </td>
      <td>
        <input
          type="checkbox"
          checked={rule.enabled}
          disabled={!canEdit || update.isPending}
          onChange={(e) => update.mutate({ enabled: e.target.checked })}
        />
      </td>
      <td>
        <input
          className="form-input"
          type="number"
          min={0}
          max={100}
          style={{ width: 70, padding: "4px 6px", fontSize: 12 }}
          value={weight}
          disabled={!canEdit}
          onChange={(e) => setWeight(e.target.value)}
        />
        {rule.weight !== rule.defaults.weight && (
          <div style={{ fontSize: 10.5, color: "var(--text-muted)" }}>default {rule.defaults.weight}</div>
        )}
      </td>
      <td>
        {Object.keys(params).length === 0 ? (
          <span style={{ color: "var(--text-muted)", fontSize: 12 }}>—</span>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "3px 8px", alignItems: "center" }}>
            {Object.entries(params).map(([key, value]) => (
              <ParamInput key={key} name={key} value={value} disabled={!canEdit}
                onChange={(v) => setParams({ ...params, [key]: v })} />
            ))}
          </div>
        )}
      </td>
      <td style={{ whiteSpace: "nowrap" }}>
        {canEdit && (
          <div style={{ display: "flex", gap: 6 }}>
            <button
              className="btn btn-primary btn-sm"
              disabled={!dirty || update.isPending}
              onClick={() =>
                update.mutate({
                  ...(Number(weight) !== rule.weight ? { weight: Number(weight) } : {}),
                  ...(Object.keys(changedParams).length ? { params: changedParams } : {}),
                })
              }
            >
              Save
            </button>
            {rule.override && (
              <button className="btn btn-secondary btn-sm" disabled={reset.isPending} onClick={() => reset.mutate()}>
                Reset
              </button>
            )}
          </div>
        )}
      </td>
    </tr>
  );
}

function ParamInput({ name, value, disabled, onChange }: { name: string; value: string; disabled: boolean; onChange: (v: string) => void }) {
  return (
    <>
      <label className="text-mono" style={{ fontSize: 10.5, color: "var(--text-muted)" }}>{name}</label>
      <input
        className="form-input"
        style={{ padding: "3px 6px", fontSize: 12, minWidth: 80 }}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
      />
    </>
  );
}

const TIMEZONES = (() => {
  try {
    return (Intl as unknown as { supportedValuesOf?: (key: string) => string[] }).supportedValuesOf?.("timeZone") ?? ["UTC"];
  } catch {
    return ["UTC"];
  }
})();

// Reporting timezone (task 025) and data retention overrides (task 029).
function ReportingSection({ canEdit }: { canEdit: boolean }) {
  const queryClient = useQueryClient();
  const { data: org } = useQuery<OrganizationResponse>({ queryKey: ["organization"], queryFn: orgApi.me });
  const [timezone, setTimezone] = useState("UTC");
  const [retention, setRetention] = useState({ raw_events_retention_days: "", sessions_retention_days: "", fraud_session_retention_days: "" });

  useEffect(() => {
    if (!org) return;
    setTimezone(org.timezone);
    setRetention({
      raw_events_retention_days: org.raw_events_retention_days?.toString() ?? "",
      sessions_retention_days: org.sessions_retention_days?.toString() ?? "",
      fraud_session_retention_days: org.fraud_session_retention_days?.toString() ?? "",
    });
  }, [org]);

  const save = useMutation({
    mutationFn: () => orgApi.update({
      timezone,
      raw_events_retention_days: retention.raw_events_retention_days ? Number(retention.raw_events_retention_days) : null,
      sessions_retention_days: retention.sessions_retention_days ? Number(retention.sessions_retention_days) : null,
      fraud_session_retention_days: retention.fraud_session_retention_days ? Number(retention.fraud_session_retention_days) : null,
    }),
    onSuccess: (data) => queryClient.setQueryData(["organization"], data),
  });

  const fields: { key: keyof typeof retention; label: string; help: string }[] = [
    { key: "raw_events_retention_days", label: "Raw events (days)", help: "Page views, clicks, scrolls. Platform default 30." },
    { key: "sessions_retention_days", label: "Sessions (days)", help: "Then anonymized: IP shortened, identifiers removed. Default 90." },
    { key: "fraud_session_retention_days", label: "Fraud sessions (days)", help: "Kept longer as fraud intelligence. Default 365." },
  ];

  return (
    <div className="card section-gap">
      <div className="card-header">
        <div>
          <h2 className="card-title">Reporting and data retention</h2>
          <div className="card-subtitle">"Today", days and hours use this timezone. Empty retention = platform default.</div>
        </div>
      </div>
      <div style={{ padding: 16, display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
        <div className="form-group" style={{ marginBottom: 0 }}>
          <label className="form-label">Reporting timezone</label>
          <select className="form-input" value={timezone} disabled={!canEdit} onChange={(e) => setTimezone(e.target.value)}>
            {(TIMEZONES.includes(timezone) ? TIMEZONES : [timezone, ...TIMEZONES]).map((tz) => <option key={tz} value={tz}>{tz}</option>)}
          </select>
        </div>
        {fields.map((f) => (
          <div key={f.key} className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">{f.label}</label>
            <input className="form-input" type="number" min={1} max={3650} placeholder="default" value={retention[f.key]}
              disabled={!canEdit} onChange={(e) => setRetention({ ...retention, [f.key]: e.target.value })} />
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 3 }}>{f.help}</div>
          </div>
        ))}
      </div>
      {save.isError && <div className="alert alert-error" style={{ margin: "0 16px 12px" }}>{errorText(save.error)}</div>}
      {canEdit && (
        <div style={{ padding: "0 16px 16px" }}>
          <button className="btn btn-primary btn-sm" disabled={save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving..." : save.isSuccess ? "Saved" : "Save"}
          </button>
        </div>
      )}
    </div>
  );
}

// Visitor data erasure (task 029). Owners only, this organization only, audited.
function PrivacySection() {
  const [kind, setKind] = useState<"visitor_token" | "ip">("visitor_token");
  const [value, setValue] = useState("");
  const erase = useMutation({ mutationFn: () => privacyApi.erase({ [kind]: value.trim() }) });
  return (
    <div className="card section-gap">
      <div className="card-header">
        <div>
          <h2 className="card-title">Erase a visitor's data</h2>
          <div className="card-subtitle">For privacy requests: deletes their events and anonymizes their sessions. Cannot be undone.</div>
        </div>
      </div>
      <form style={{ display: "flex", gap: 8, padding: 16, flexWrap: "wrap" }}
        onSubmit={(e) => { e.preventDefault(); if (window.confirm("Erase this visitor's data? This cannot be undone.")) erase.mutate(); }}>
        <select className="form-input" style={{ width: "auto" }} value={kind} onChange={(e) => setKind(e.target.value as "visitor_token" | "ip")}>
          <option value="visitor_token">Visitor ID</option>
          <option value="ip">IP address</option>
        </select>
        <input className="form-input" style={{ maxWidth: 320 }} value={value} onChange={(e) => setValue(e.target.value)} required
          placeholder={kind === "ip" ? "203.0.113.7" : "v_..."} />
        <button className="btn btn-secondary btn-sm" disabled={erase.isPending}>Erase</button>
      </form>
      {erase.isError && <div className="alert alert-error" style={{ margin: "0 16px 16px" }}>{errorText(erase.error)}</div>}
      {erase.data && (
        <div className="alert alert-success" style={{ margin: "0 16px 16px" }}>
          Done: {erase.data.sessions_anonymized} session(s) anonymized, {erase.data.events_deleted} event(s) and{" "}
          {erase.data.visitors_deleted} visitor record(s) deleted.
        </div>
      )}
    </div>
  );
}
