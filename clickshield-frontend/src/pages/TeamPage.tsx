import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { teamApi } from "../services/p3Api";
import { useCan } from "../lib/permissions";
import { useAuthStore } from "../store/authStore";
import { fmtDate } from "../lib/utils";
import { Card, Loading, Topbar, errorText } from "../components/ui";
import type { Invitation, Member, UserRole } from "../types/api";

const ROLES: UserRole[] = ["member", "admin", "owner"];
const ROLE_HELP: Record<UserRole, string> = {
  member: "views dashboards and gives feedback",
  admin: "also configures websites, Google Ads, protection and alerts",
  owner: "also manages the team and privacy requests",
};

// Task 030: members, roles and invitations.
export default function TeamPage() {
  const canManage = useCan("users:manage");
  const me = useAuthStore((s) => s.user);
  const queryClient = useQueryClient();
  const members = useQuery<Member[]>({ queryKey: ["members"], queryFn: teamApi.members });
  const invitations = useQuery<Invitation[]>({ queryKey: ["invitations"], queryFn: teamApi.invitations, enabled: canManage });
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<UserRole>("member");
  const [lastLink, setLastLink] = useState<string | null>(null);
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["members"] });
    queryClient.invalidateQueries({ queryKey: ["invitations"] });
  };
  const invite = useMutation({
    mutationFn: () => teamApi.invite(email, role),
    onSuccess: (inv) => { setLastLink(inv.invite_url ?? null); setEmail(""); refresh(); },
  });
  const update = useMutation({ mutationFn: ({ id, body }: { id: string; body: { role?: UserRole; is_active?: boolean } }) => teamApi.update(id, body), onSuccess: refresh });
  const revoke = useMutation({ mutationFn: teamApi.revoke, onSuccess: refresh });
  const prefs = useMutation({ mutationFn: teamApi.myPreferences, onSuccess: refresh });
  const mine = members.data?.find((m) => m.id === me?.id);

  return (
    <>
      <Topbar title="Team" />
      <main className="page-body">
        <div className="page-header">
          <h1>Team and roles</h1>
          <p>{ROLES.map((r) => `${r[0].toUpperCase()}${r.slice(1)}: ${ROLE_HELP[r]}`).join(". ")}.</p>
        </div>

        {mine && (
          <Card title="My alert emails">
            <label style={{ display: "flex", gap: 8, padding: 16, fontSize: 13, alignItems: "center" }}>
              <input type="checkbox" checked={mine.alert_emails} onChange={(e) => prefs.mutate(e.target.checked)} />
              Email me alerts (owners and admins receive them)
            </label>
          </Card>
        )}

        {canManage && (
          <Card title="Invite someone" subtitle="They get an email with a link valid for 72 hours.">
            <form style={{ display: "flex", gap: 8, padding: 16, flexWrap: "wrap" }} onSubmit={(e) => { e.preventDefault(); invite.mutate(); }}>
              <input className="form-input" style={{ maxWidth: 300 }} type="email" placeholder="name@company.com" value={email}
                onChange={(e) => setEmail(e.target.value)} required />
              <select className="form-input" style={{ width: "auto" }} value={role} onChange={(e) => setRole(e.target.value as UserRole)}>
                {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
              <button className="btn btn-primary btn-sm" disabled={invite.isPending}>Send invitation</button>
            </form>
            {invite.isError && <div className="alert alert-error" style={{ margin: "0 16px 16px" }}>{errorText(invite.error)}</div>}
            {lastLink && (
              <div className="alert alert-success" style={{ margin: "0 16px 16px", wordBreak: "break-all" }}>
                Invitation sent. You can also share this link: <span className="text-mono">{lastLink}</span>
              </div>
            )}
          </Card>
        )}

        <Card title="Members">
          {members.isLoading ? <Loading /> : (
            <div className="table-wrap"><table>
              <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Joined</th></tr></thead>
              <tbody>{members.data?.map((m) => (
                <tr key={m.id}>
                  <td>{m.full_name ?? "—"}{m.id === me?.id && <span className="chip" style={{ marginLeft: 6 }}>you</span>}</td>
                  <td>{m.email}</td>
                  <td>{canManage ? (
                    <select className="form-input" style={{ width: "auto", padding: "3px 6px", fontSize: 12 }} value={m.role}
                      onChange={(e) => update.mutate({ id: m.id, body: { role: e.target.value as UserRole } })}>
                      {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>) : m.role}</td>
                  <td>{canManage ? (
                    <button className="btn btn-secondary btn-sm" onClick={() => update.mutate({ id: m.id, body: { is_active: !m.is_active } })}>
                      {m.is_active ? "Deactivate" : "Reactivate"}</button>) : (m.is_active ? "Active" : "Deactivated")}</td>
                  <td style={{ fontSize: 12 }}>{fmtDate(m.created_at)}</td>
                </tr>))}</tbody>
            </table></div>
          )}
          {update.isError && <div className="alert alert-error" style={{ margin: 16 }}>{errorText(update.error)}</div>}
        </Card>

        {canManage && !!invitations.data?.length && (
          <Card title="Open invitations">
            <div className="table-wrap"><table>
              <thead><tr><th>Email</th><th>Role</th><th>Expires</th><th /></tr></thead>
              <tbody>{invitations.data.map((i) => (
                <tr key={i.id}><td>{i.email}</td><td>{i.role}</td><td style={{ fontSize: 12 }}>{fmtDate(i.expires_at)}</td>
                  <td><button className="btn btn-secondary btn-sm" onClick={() => revoke.mutate(i.id)}>Revoke</button></td></tr>))}</tbody>
            </table></div>
          </Card>
        )}
      </main>
    </>
  );
}

export function AcceptInvitePage() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const navigate = useNavigate();
  const setAuth = useAuthStore((s) => s.setAuth);
  const preview = useQuery({ queryKey: ["invite", token], queryFn: () => teamApi.previewInvite(token), enabled: !!token, retry: false });
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const accept = useMutation({
    mutationFn: () => teamApi.acceptInvite(token, name, password),
    onSuccess: (data) => {
      setAuth({ user: data.user, organization: data.organization, accessToken: data.tokens.access_token, refreshToken: data.tokens.refresh_token });
      navigate("/");
    },
  });
  return (
    <div style={{ maxWidth: 420, margin: "80px auto", padding: 16 }}>
      <div className="card" style={{ padding: 24 }}>
        <h1 style={{ fontSize: 20, marginBottom: 12 }}>Join Click Shield</h1>
        {!token || preview.isError ? <div className="alert alert-error">This invitation is invalid or has expired.</div>
          : preview.isLoading ? <Loading /> : (
          <form onSubmit={(e) => { e.preventDefault(); accept.mutate(); }}>
            <p style={{ fontSize: 13 }}>You're invited to <strong>{preview.data?.organization_name}</strong> as {preview.data?.role}, with {preview.data?.email}.</p>
            <div className="form-group"><label className="form-label">Your name</label>
              <input className="form-input" value={name} onChange={(e) => setName(e.target.value)} required minLength={2} /></div>
            <div className="form-group"><label className="form-label">Choose a password</label>
              <input className="form-input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} />
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>At least 8 characters, with letters and a number.</div></div>
            {accept.isError && <div className="alert alert-error">{errorText(accept.error)}</div>}
            <button className="btn btn-primary" disabled={accept.isPending}>Join</button>
          </form>
        )}
      </div>
    </div>
  );
}
