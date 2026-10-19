import { lazy, Suspense } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import AppLayout from "./components/AppLayout";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import OverviewPage from "./pages/OverviewPage";
import SessionsPage from "./pages/SessionsPage";
import SessionDetailPage from "./pages/SessionDetailPage";
import FraudEventsPage from "./pages/FraudEventsPage";
import TopIPsPage from "./pages/TopIPsPage";
import ProtectionPage from "./pages/ProtectionPage";
import GooglePage from "./pages/GooglePage";
import GoogleCallback from "./pages/GoogleCallback";
import WebsitesPage from "./pages/WebsitesPage";
import AlertsPage from "./pages/AlertsPage";
import TeamPage, { AcceptInvitePage } from "./pages/TeamPage";
import AuditLogPage from "./pages/AuditLogPage";
import SettingsPage from "./pages/SettingsPage";

// Chart pages (Recharts) load on demand to keep the first load small.
const AnalyticsPage = lazy(() => import("./pages/AnalyticsPage"));
const CampaignsPage = lazy(() => import("./pages/CampaignsPage"));
const CampaignDetailPage = lazy(() => import("./pages/CampaignsPage").then((m) => ({ default: m.CampaignDetailPage })));
const AdminPage = lazy(() => import("./pages/AdminPage"));

export default function App() {
  return (
    <Suspense fallback={<div className="empty-state"><div className="spinner" /></div>}>
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/accept-invite" element={<AcceptInvitePage />} />
      <Route element={<AppLayout />}>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/sessions" element={<SessionsPage />} />
        <Route path="/sessions/:id" element={<SessionDetailPage />} />
        <Route path="/fraud-events" element={<FraudEventsPage />} />
        <Route path="/top-ips" element={<TopIPsPage />} />
        <Route path="/analytics" element={<AnalyticsPage />} />
        <Route path="/campaigns" element={<CampaignsPage />} />
        <Route path="/campaigns/:id" element={<CampaignDetailPage />} />
        <Route path="/protection" element={<ProtectionPage />} />
        <Route path="/google" element={<GooglePage />} />
        <Route path="/google/callback" element={<GoogleCallback />} />
        <Route path="/websites" element={<WebsitesPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/team" element={<TeamPage />} />
        <Route path="/audit-log" element={<AuditLogPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/admin" element={<AdminPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
    </Suspense>
  );
}
