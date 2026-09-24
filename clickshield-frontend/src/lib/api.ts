import axios from "axios";

const BASE = "/api/v1";

export const api = axios.create({ baseURL: BASE });

// ─── Request: inject Bearer token ────────────────────────────────────────────
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("cs_access_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// ─── Response: 401 → try silent token refresh, then redirect ─────────────────
let isRefreshing = false;
let pendingQueue: Array<{
  resolve: (value: string) => void;
  reject: (err: unknown) => void;
}> = [];

function flushQueue(token: string | null, err: unknown = null) {
  pendingQueue.forEach(({ resolve, reject }) => {
    if (token) resolve(token);
    else reject(err);
  });
  pendingQueue = [];
}

api.interceptors.response.use(
  (r) => r,
  async (err) => {
    const originalRequest = err.config;

    // Only attempt refresh on 401, once per request, and not on auth routes
    if (
      err.response?.status === 401 &&
      !originalRequest._retry &&
      !originalRequest.url?.includes("/auth/")
    ) {
      if (isRefreshing) {
        // Queue subsequent 401s while refresh is in flight
        return new Promise<string>((resolve, reject) => {
          pendingQueue.push({ resolve, reject });
        }).then((newToken) => {
          originalRequest.headers.Authorization = `Bearer ${newToken}`;
          return api(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      const refreshToken = localStorage.getItem("cs_refresh_token");

      if (!refreshToken) {
        isRefreshing = false;
        localStorage.removeItem("cs_access_token");
        window.location.href = "/login";
        return Promise.reject(err);
      }

      try {
        const { data } = await axios.post(`${BASE}/auth/refresh`, {
          refresh_token: refreshToken,
        });

        const newAccessToken: string = data.access_token;
        localStorage.setItem("cs_access_token", newAccessToken);

        flushQueue(newAccessToken);
        isRefreshing = false;

        originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
        return api(originalRequest);
      } catch (refreshErr) {
        flushQueue(null, refreshErr);
        isRefreshing = false;
        localStorage.removeItem("cs_access_token");
        localStorage.removeItem("cs_refresh_token");
        window.location.href = "/login";
        return Promise.reject(refreshErr);
      }
    }

    return Promise.reject(err);
  }
);
