import { Routes, Route, Navigate } from "react-router-dom";
import AppLayout from "./components/AppLayout";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import OverviewPage from "./pages/OverviewPage";
import SessionsPage from "./pages/SessionsPage";
import FraudEventsPage from "./pages/FraudEventsPage";
import TopIPsPage from "./pages/TopIPsPage";
import ProtectionPage from "./pages/ProtectionPage";
import GooglePage from "./pages/GooglePage";
import AuditLogPage from "./pages/AuditLogPage";
import SettingsPage from "./pages/SettingsPage";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route element={<AppLayout />}>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/sessions" element={<SessionsPage />} />
        <Route path="/fraud-events" element={<FraudEventsPage />} />
        <Route path="/top-ips" element={<TopIPsPage />} />
        <Route path="/protection" element={<ProtectionPage />} />
        <Route path="/google" element={<GooglePage />} />
        <Route path="/audit-log" element={<AuditLogPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
