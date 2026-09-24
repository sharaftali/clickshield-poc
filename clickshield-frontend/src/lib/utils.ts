import type { Verdict, ExclusionStatus } from "../types/api";

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
  };
  return map[status] ?? "badge";
}

export function riskColor(score: number): string {
  if (score >= 80) return "var(--red)";
  if (score >= 50) return "var(--amber)";
  return "var(--green)";
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
