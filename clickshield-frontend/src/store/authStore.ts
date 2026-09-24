import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { UserPublic, OrganizationSummary } from "../types/api";

interface AuthState {
  user: UserPublic | null;
  organization: OrganizationSummary | null;
  accessToken: string | null;
  refreshToken: string | null;
  setAuth: (data: {
    user: UserPublic;
    organization: OrganizationSummary;
    accessToken: string;
    refreshToken: string;
  }) => void;
  clearAuth: () => void;
  isAuthenticated: () => boolean;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      organization: null,
      accessToken: null,
      refreshToken: null,
      setAuth: ({ user, organization, accessToken, refreshToken }) => {
        localStorage.setItem("cs_access_token", accessToken);
        localStorage.setItem("cs_refresh_token", refreshToken);
        set({ user, organization, accessToken, refreshToken });
      },
      clearAuth: () => {
        localStorage.removeItem("cs_access_token");
        localStorage.removeItem("cs_refresh_token");
        set({ user: null, organization: null, accessToken: null, refreshToken: null });
      },
      isAuthenticated: () => !!get().accessToken,
    }),
    { name: "cs_auth" }
  )
);
