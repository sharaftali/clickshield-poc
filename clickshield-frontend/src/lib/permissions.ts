// Mirror of backend/app/dependencies/permissions.py (task 030), used to hide controls.
// The server enforces every permission; this only avoids showing buttons that would 403.
import { useAuthStore } from "../store/authStore";
import type { UserRole } from "../types/api";

const RANK: Record<UserRole, number> = { member: 1, admin: 2, owner: 3 };

const PERMISSIONS = {
  "dashboard:view": "member",
  "sessions:feedback": "member",
  "websites:manage": "admin",
  "google:manage": "admin",
  "protection:manage": "admin",
  "exclusions:manage": "admin",
  "alerts:manage": "admin",
  "settings:manage": "admin",
  "users:manage": "owner",
  "privacy:erase": "owner",
} as const satisfies Record<string, UserRole>;

export type Permission = keyof typeof PERMISSIONS;

export function roleAllows(role: string | null | undefined, permission: Permission): boolean {
  const current = RANK[(role ?? "").toLowerCase() as UserRole] ?? 0;
  return current >= RANK[PERMISSIONS[permission]];
}

export function useCan(permission: Permission): boolean {
  const role = useAuthStore((s) => s.user?.role);
  return roleAllows(role, permission);
}

export function useIsPlatformAdmin(): boolean {
  return useAuthStore((s) => !!s.user?.is_platform_admin);
}
