import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { authApi } from "../services/apiService";
import { useAuthStore } from "../store/authStore";

export default function LoginPage() {
  const navigate = useNavigate();
  const setAuth = useAuthStore((s) => s.setAuth);
  const [email, setEmail] = useState("admin@gmail.com");
  const [password, setPassword] = useState("ChangeMe@123");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const data = await authApi.login({ email, password });
      setAuth({
        user: data.user,
        organization: data.organization,
        accessToken: data.tokens.access_token,
        refreshToken: data.tokens.refresh_token,
      });
      navigate("/");
    } catch (err: unknown) {
      const msg =
        (err as { response?: { data?: { detail?: string } } })?.response?.data
          ?.detail ?? "Login failed. Check your credentials.";
      setError(typeof msg === "string" ? msg : "Login failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-brand">
          <div className="login-brand-mark">
            <svg width="18" height="18" viewBox="0 0 16 16" fill="white">
              <path d="M8 1L13.5 3.5V7.5C13.5 10.5 11 13 8 14C5 13 2.5 10.5 2.5 7.5V3.5L8 1Z" />
            </svg>
          </div>
          <span className="login-brand-text">ClickShield</span>
        </div>

        <h1 style={{ fontSize: 18, fontWeight: 700, marginBottom: 4, letterSpacing: "-0.02em" }}>
          Sign in
        </h1>
        <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 24 }}>
          Enter your credentials to access the dashboard.
        </p>

        {error && <div className="alert alert-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label" htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              className="form-input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              className="form-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary form-submit"
            disabled={loading}
          >
            {loading ? <><span className="spinner" style={{ width: 14, height: 14 }} />Signing in…</> : "Sign in"}
          </button>
        </form>

        <div style={{ marginTop: 22, textAlign: "center", fontSize: 13, color: "var(--text-muted)" }}>
          Don't have an account?{" "}
          <Link to="/register" style={{ color: "var(--blue)", fontWeight: 600 }}>
            Create workspace
          </Link>
        </div>
      </div>
    </div>
  );
}
