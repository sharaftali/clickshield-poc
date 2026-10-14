import type { Verdict, ExclusionStatus, RiskBand, RuleCategory } from "../types/api";

export function verdictBadge(verdict: Verdict): string {
  const map: Record<Verdict, string> = {
    SAFE: "badge badge-safe",
    MONITOR: "badge badge-monitor",
    FLAG: "badge badge-flag",
    FRAUD: "badge badge-fraud",
  };
  return map[verdict] ?? "badge";
}

export function exclusionBadge(status: ExclusionStatus): string {
  const map: Record<ExclusionStatus, string> = {
    PENDING: "badge badge-pending",
    SUBMITTED: "badge badge-submitted",
    ACTIVE: "badge badge-active",
    FAILED: "badge badge-failed",
    REMOVED: "badge badge-removed",
    SKIPPED: "badge badge-removed",
  };
  return map[status] ?? "badge";
}

// Spec §24 bands: 0–29 LOW, 30–59 MODERATE, 60–79 HIGH, 80+ VERY HIGH.
export function riskColor(score: number): string {
  if (score >= 80) return "var(--red)";
  if (score >= 30) return "var(--amber)";
  return "var(--green)";
}

export function bandLabel(band: RiskBand | null | undefined): string {
  const map: Record<RiskBand, string> = {
    LOW: "Low risk",
    MODERATE: "Moderate risk",
    HIGH: "High risk",
    VERY_HIGH: "Very high risk",
  };
  return band ? map[band] ?? band : "—";
}

/** [category, points] sorted by contribution, largest first. */
export function categoryList(categories: Partial<Record<RuleCategory, number>> | null | undefined): [RuleCategory, number][] {
  return Object.entries(categories ?? {})
    .filter(([, points]) => (points ?? 0) > 0)
    .sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0)) as [RuleCategory, number][];
}

export function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function fmtNumber(n: number): string {
  return n.toLocaleString();
}

export function initials(name: string | null | undefined): string {
  if (!name) return "?";
  return name
    .trim()
    .split(/\s+/)
    .map((w) => w[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
}
