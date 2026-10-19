import { useEffect, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { googleApi } from "../services/apiService";

/**
 * Google redirects here after consent (GOOGLE_OAUTH_REDIRECT_URI). The code and state are
 * posted with this user's Bearer token, so the backend can check that the state was started
 * by the same user and organization (SEC-01).
 */
export default function GoogleCallback() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  // The state is single-use: React StrictMode runs effects twice in development.
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;

    const code = searchParams.get("code");
    const state = searchParams.get("state");
    const fail = (message: string) =>
      navigate(`/google?${new URLSearchParams({ google_oauth_status: "error", google_oauth_message: message })}`, {
        replace: true,
      });

    if (searchParams.get("error") || !code || !state) {
      fail("Google did not complete the connection. Please try again.");
      return;
    }

    googleApi
      .complete({ code, state })
      .then(() =>
        navigate(
          `/google?${new URLSearchParams({
            google_oauth_status: "success",
            google_oauth_message:
              "Google Ads connected successfully. Select a customer account to continue protection setup.",
          })}`,
          { replace: true },
        ),
      )
      .catch((err: any) => fail(err?.response?.data?.detail ?? "Could not connect Google Ads. Please try again."));
  }, [navigate, searchParams]);

  return (
    <main className="page-body">
      <div className="empty-state">
        <div className="spinner" />
        <span>Connecting Google Ads…</span>
      </div>
    </main>
  );
}
