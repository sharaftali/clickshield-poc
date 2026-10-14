import type { ReactElement } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useAuthStore } from "../store/authStore";
import { alertsApi } from "../services/p3Api";
import { initials } from "../lib/utils";

type NavItem = { to: string; label: string; icon: (p: { size: number }) => ReactElement };

const SECTIONS: { label: string; items: NavItem[] }[] = [
  { label: "Monitoring", items: [
    { to: "/", label: "Overview", icon: GridIcon },
    { to: "/analytics", label: "Analytics", icon: ChartIcon },
    { to: "/campaigns", label: "Campaigns", icon: ListIcon },
    { to: "/sessions", label: "Sessions", icon: ListIcon },
    { to: "/fraud-events", label: "Fraud Events", icon: AlertIcon },
    { to: "/top-ips", label: "Top IPs", icon: IpIcon },
  ] },
  { label: "Protection", items: [
    { to: "/protection", label: "Protection", icon: ShieldIcon },
    { to: "/google", label: "Google Ads", icon: GoogleIcon },
    { to: "/websites", label: "Websites", icon: IpIcon },
    { to: "/alerts", label: "Alerts", icon: BellIcon },
  ] },
  { label: "Organization", items: [
    { to: "/team", label: "Team", icon: AuditIcon },
    { to: "/audit-log", label: "Audit Log", icon: AuditIcon },
    { to: "/settings", label: "Settings", icon: SettingsIcon },
  ] },
];

export default function Sidebar() {
  const { user, organization, clearAuth } = useAuthStore();
  const navigate = useNavigate();
  // Alert bell (task 028): open alerts, refreshed every minute.
  const { data: alerts } = useQuery({ queryKey: ["alerts-summary"], queryFn: alertsApi.summary, refetchInterval: 60000 });
  const sections = user?.is_platform_admin
    ? [...SECTIONS, { label: "Platform", items: [{ to: "/admin", label: "Admin", icon: ShieldIcon }] }]
    : SECTIONS;

  const handleLogout = () => {
    clearAuth();
    navigate("/login");
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="sidebar-logo-mark">
          <ShieldSolidIcon />
        </div>
        <div>
          <div className="sidebar-logo-text">ClickShield</div>
          <div className="sidebar-logo-sub">Fraud protection</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {sections.map((section, index) => (
          <div key={section.label}>
            <span className="nav-section-label" style={index ? { marginTop: 8 } : undefined}>{section.label}</span>
            {section.items.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                end={to === "/"}
                className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}
              >
                <Icon size={15} />
                {label}
                {to === "/alerts" && !!alerts?.open && (
                  <span
                    className={alerts.critical ? "badge badge-fraud" : "badge badge-monitor"}
                    style={{ marginLeft: "auto", fontSize: 10, padding: "0 6px" }}
                    title={`${alerts.open} open alert(s)`}
                  >
                    {alerts.open}
                  </span>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="org-chip">
          <div className="org-avatar">
            {initials(organization?.name)}
          </div>
          <div className="org-info">
            <div className="org-name">{organization?.name ?? "Organization"}</div>
            <div className="org-role">{user?.role?.toLowerCase()}</div>
          </div>
        </div>
        <button className="btn-logout" onClick={handleLogout}>
          <LogoutIcon size={14} />
          Sign out
        </button>
      </div>
    </aside>
  );
}

/* ── Inline SVG icons (no lucide) ─────────────────────────────────────────── */
function Icon({ size, children }: { size: number; children: React.ReactNode }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor"
      strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      {children}
    </svg>
  );
}

function ChartIcon({ size }: { size: number }) {
  return <Icon size={size}><polyline points="1.5 12 5.5 7.5 9 10 14.5 3.5"/><line x1="1.5" y1="14.5" x2="14.5" y2="14.5"/></Icon>;
}
function BellIcon({ size }: { size: number }) {
  return <Icon size={size}><path d="M4 11V7a4 4 0 018 0v4l1.5 1.5h-11z"/><path d="M6.5 14a1.5 1.5 0 003 0"/></Icon>;
}
function GridIcon({ size }: { size: number }) {
  return <Icon size={size}><rect x="1" y="1" width="6" height="6" rx="1"/><rect x="9" y="1" width="6" height="6" rx="1"/><rect x="1" y="9" width="6" height="6" rx="1"/><rect x="9" y="9" width="6" height="6" rx="1"/></Icon>;
}
function ListIcon({ size }: { size: number }) {
  return <Icon size={size}><line x1="2" y1="4" x2="14" y2="4"/><line x1="2" y1="8" x2="14" y2="8"/><line x1="2" y1="12" x2="14" y2="12"/></Icon>;
}
function AlertIcon({ size }: { size: number }) {
  return <Icon size={size}><path d="M8 2L14.5 13.5H1.5L8 2z"/><line x1="8" y1="7" x2="8" y2="10"/><circle cx="8" cy="12" r="0.5" fill="currentColor" stroke="none"/></Icon>;
}
function IpIcon({ size }: { size: number }) {
  return <Icon size={size}><circle cx="8" cy="8" r="6.5"/><path d="M1.5 8h13M8 1.5a11 11 0 010 13M8 1.5a11 11 0 000 13"/></Icon>;
}
function ShieldIcon({ size }: { size: number }) {
  return <Icon size={size}><path d="M8 1.5l5.5 2v4c0 3-2.5 5.5-5.5 6.5C5 13 2.5 10.5 2.5 7.5v-4L8 1.5z"/></Icon>;
}
function GoogleIcon({ size }: { size: number }) {
  return <Icon size={size}><path d="M14 8.1c0-.5-.1-.9-.2-1.3H8v2.5h3.4a2.9 2.9 0 01-1.3 1.9v1.6h2.1C13.4 11.6 14 10 14 8.1z"/><path d="M8 14c1.7 0 3.1-.6 4.2-1.5l-2.1-1.6c-.6.4-1.3.6-2.1.6-1.6 0-3-1.1-3.5-2.5H2.4v1.6C3.5 12.7 5.6 14 8 14z"/><path d="M4.5 9c-.1-.4-.2-.8-.2-1.2S4.4 7 4.5 6.6V5H2.4A6 6 0 002 7.8c0 1 .2 2 .5 2.8L4.5 9z"/><path d="M8 3.8c.9 0 1.7.3 2.3.9l1.8-1.8C11.1 2 9.7 1.4 8 1.4 5.6 1.4 3.5 2.7 2.4 4.6L4.5 6.2C5 4.8 6.4 3.8 8 3.8z"/></Icon>;
}
function AuditIcon({ size }: { size: number }) {
  return <Icon size={size}><path d="M4 1.5h6l3 3V14a.5.5 0 01-.5.5h-8.5A.5.5 0 013.5 14V2a.5.5 0 01.5-.5z"/><polyline points="10 1.5 10 4.5 13 4.5"/><line x1="5.5" y1="8" x2="10.5" y2="8"/><line x1="5.5" y1="10.5" x2="10.5" y2="10.5"/></Icon>;
}

function SettingsIcon({ size }: { size: number }) {
  return <Icon size={size}><line x1="2" y1="4" x2="14" y2="4"/><line x1="2" y1="8" x2="14" y2="8"/><line x1="2" y1="12" x2="14" y2="12"/><circle cx="5" cy="4" r="1.5" fill="white"/><circle cx="10.5" cy="8" r="1.5" fill="white"/><circle cx="7" cy="12" r="1.5" fill="white"/></Icon>;
}

function ShieldSolidIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="white" stroke="none">
      <path d="M8 1L13.5 3.5V7.5C13.5 10.5 11 13 8 14C5 13 2.5 10.5 2.5 7.5V3.5L8 1Z" />
    </svg>
  );
}
function LogoutIcon({ size }: { size: number }) {
  return <Icon size={size}><path d="M6 2H3a1 1 0 00-1 1v10a1 1 0 001 1h3"/><polyline points="10 11 14 8 10 5"/><line x1="14" y1="8" x2="5" y2="8"/></Icon>;
}
