import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { authApi } from "../services/apiService";
import { useAuthStore } from "../store/authStore";
import type { ProtectionMode } from "../types/api";

export default function RegisterPage() {
  const navigate = useNavigate();
  const setAuth = useAuthStore((s) => s.setAuth);

  const [fullName, setFullName] = useState("");
  const [orgName, setOrgName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [protectionMode, setProtectionMode] = useState<ProtectionMode>("balanced");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    setLoading(true);
    try {
      const data = await authApi.register({
        full_name: fullName.trim(),
        organization_name: orgName.trim(),
        email: email.trim(),
        password,
        protection_mode: protectionMode,
      });

      setAuth({
        user: data.user,
        organization: data.organization,
        accessToken: data.tokens.access_token,
        refreshToken: data.tokens.refresh_token,
      });

      navigate("/");
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string | Array<{ msg: string }> } } })?.response?.data?.detail;
      let msg = "Registration failed. Please check your inputs.";
      if (typeof detail === "string") {
        msg = detail;
      } else if (Array.isArray(detail) && detail[0]?.msg) {
        msg = detail[0].msg;
      }
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card glass-panel" style={{ maxWidth: 440 }}>
        <div className="login-brand">
          <div className="login-brand-mark">
            <svg width="20" height="20" viewBox="0 0 16 16" fill="white">
              <path d="M8 1L13.5 3.5V7.5C13.5 10.5 11 13 8 14C5 13 2.5 10.5 2.5 7.5V3.5L8 1Z" />
            </svg>
          </div>
          <div>
            <span className="login-brand-text">ClickShield</span>
            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>Ad Fraud Detection Platform</div>
          </div>
        </div>

        <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 4, letterSpacing: "-0.02em" }}>
          Create an account
        </h1>
        <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 20 }}>
          Start safeguarding your Google Ads campaigns in minutes.
        </p>

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label" htmlFor="fullName">Full Name</label>
            <input
              id="fullName"
              type="text"
              className="form-input"
              placeholder="e.g. Alex Vance"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              required
              minLength={2}
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="orgName">Organization / Company Name</label>
            <input
              id="orgName"
              type="text"
              className="form-input"
              placeholder="e.g. Acme Media Corp"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              required
              minLength={2}
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="email">Business Email</label>
            <input
              id="email"
              type="email"
              className="form-input"
              placeholder="alex@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="password">Password (8+ characters)</label>
            <input
              id="password"
              type="password"
              className="form-input"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
              autoComplete="new-password"
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="mode">Initial Protection Mode</label>
            <select
              id="mode"
              className="form-input"
              value={protectionMode}
              onChange={(e) => setProtectionMode(e.target.value as ProtectionMode)}
            >
              <option value="balanced">Balanced (Recommended - Optimal Detection &amp; Safety)</option>
              <option value="aggressive">Aggressive (Faster Automated Protection)</option>
              <option value="conservative">Conservative (Lower False Positive Risk)</option>
              <option value="custom">Custom (Reserved for future advanced controls)</option>
            </select>
          </div>

          <button
            type="submit"
            className="btn btn-primary form-submit"
            disabled={loading}
            style={{ marginTop: 12 }}
          >
            {loading ? (
              <>
                <span className="spinner" style={{ width: 14, height: 14 }} />
                Setting up workspace…
              </>
            ) : (
              "Create Organization Workspace"
            )}
          </button>
        </form>

        <div style={{ marginTop: 22, textAlign: "center", fontSize: 13, color: "var(--text-muted)" }}>
          Already have an account?{" "}
          <Link to="/login" style={{ color: "var(--blue)", fontWeight: 600 }}>
            Sign in
          </Link>
        </div>
      </div>
    </div>
  );
}
