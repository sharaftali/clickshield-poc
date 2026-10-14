import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { websitesApi } from "../services/p3Api";
import { useCan } from "../lib/permissions";
import { fmtDate } from "../lib/utils";
import { Card, Empty, Loading, Topbar, errorText } from "../components/ui";
import type { Website } from "../types/api";

// Task 023: add a website, install the snippet, get verified.
export default function WebsitesPage() {
  const canManage = useCan("websites:manage");
  const queryClient = useQueryClient();
  const { data: websites, isLoading } = useQuery<Website[]>({ queryKey: ["websites"], queryFn: websitesApi.list, refetchInterval: 15000 });
  const [domain, setDomain] = useState("");
  const [consent, setConsent] = useState(false);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["websites"] });
  const create = useMutation({
    mutationFn: () => websitesApi.create({ domain, require_consent: consent }),
    onSuccess: () => { setDomain(""); setConsent(false); refresh(); },
  });

  return (
    <>
      <Topbar title="Websites" />
      <main className="page-body">
        <div className="page-header">
          <h1>Websites and tracking</h1>
          <p>
            Add your website, paste the snippet into every page (before <code>&lt;/head&gt;</code>), then open the site
            once. The first event from your domain verifies it. Events from other domains are rejected.
          </p>
        </div>

        {canManage && (
          <Card title="Add a website">
            <form
              style={{ display: "flex", gap: 10, padding: 16, flexWrap: "wrap", alignItems: "center" }}
              onSubmit={(e) => { e.preventDefault(); create.mutate(); }}
            >
              <input className="form-input" style={{ maxWidth: 320 }} placeholder="example.com" value={domain}
                onChange={(e) => setDomain(e.target.value)} required />
              <label style={{ fontSize: 13, display: "flex", gap: 6, alignItems: "center" }}>
                <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
                Wait for visitor consent before tracking
              </label>
              <button className="btn btn-primary btn-sm" disabled={!domain || create.isPending}>
                {create.isPending ? "Adding..." : "Add website"}
              </button>
              {create.isError && <span style={{ color: "var(--red)", fontSize: 12 }}>{errorText(create.error)}</span>}
            </form>
          </Card>
        )}

        {isLoading ? <Loading /> : !websites?.length ? (
          <Card><Empty>No websites yet{canManage ? ": add one above." : "."}</Empty></Card>
        ) : websites.map((w) => <WebsiteCard key={w.id} website={w} canManage={canManage} onChange={refresh} />)}
      </main>
    </>
  );
}

function WebsiteCard({ website, canManage, onChange }: { website: Website; canManage: boolean; onChange: () => void }) {
  const [copied, setCopied] = useState(false);
  const [extra, setExtra] = useState(website.allowed_domains.join(", "));
  const verify = useMutation({ mutationFn: () => websitesApi.verify(website.id), onSuccess: onChange });
  const rotate = useMutation({ mutationFn: () => websitesApi.rotateToken(website.id), onSuccess: onChange });
  const remove = useMutation({ mutationFn: () => websitesApi.remove(website.id), onSuccess: onChange });
  const update = useMutation({
    mutationFn: (body: Parameters<typeof websitesApi.update>[1]) => websitesApi.update(website.id, body),
    onSuccess: onChange,
  });
  const error = verify.error ?? rotate.error ?? remove.error ?? update.error;

  const copy = async () => {
    await navigator.clipboard.writeText(website.snippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <Card
      title={website.display_name}
      subtitle={
        <span>
          {website.domain} ·{" "}
          {website.is_verified ? (
            <span className="badge badge-active">Verified{website.verification_method ? ` (${website.verification_method.replace("_", " ")})` : ""}</span>
          ) : (
            <span className="badge badge-monitor">Waiting for the first event</span>
          )}{" "}
          · last event {website.last_event_at ? fmtDate(website.last_event_at) : "never"}
        </span>
      }
      actions={canManage && (
        <div style={{ display: "flex", gap: 6 }}>
          <button className="btn btn-secondary btn-sm" onClick={() => verify.mutate()} disabled={verify.isPending}>
            {verify.isPending ? "Checking..." : "Check now"}
          </button>
          <button className="btn btn-secondary btn-sm" disabled={rotate.isPending}
            onClick={() => window.confirm("The current token stops working immediately. Install the new snippet right after. Continue?") && rotate.mutate()}>
            Rotate token
          </button>
          <button className="btn btn-secondary btn-sm" disabled={remove.isPending}
            onClick={() => window.confirm(`Stop tracking ${website.domain}? History is kept.`) && remove.mutate()}>
            Remove
          </button>
        </div>
      )}
    >
      <div style={{ padding: 16, display: "grid", gap: 12 }}>
        {verify.data && (
          <div className={`alert ${verify.data.verified ? "alert-success" : "alert-error"}`}>{verify.data.detail}</div>
        )}
        {error && <div className="alert alert-error">{errorText(error)}</div>}
        <div>
          <div className="form-label">Install snippet</div>
          <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
            <pre className="text-mono" style={{ flex: 1, margin: 0, padding: 10, fontSize: 12, whiteSpace: "pre-wrap",
              wordBreak: "break-all", background: "var(--bg-subtle, #f6f7f9)", borderRadius: 6 }}>{website.snippet}</pre>
            <button className="btn btn-secondary btn-sm" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
          </div>
          <div style={{ fontSize: 11.5, color: "var(--text-muted)", marginTop: 4 }}>
            Or verify without installing yet: add{" "}
            <code>{`<meta name="clickshield-verification" content="${website.tracking_token}">`}</code> to your home page and click Check now.
          </div>
        </div>
        {canManage && (
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: "center", fontSize: 13 }}>
            <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <input type="checkbox" checked={website.require_consent} onChange={(e) => update.mutate({ require_consent: e.target.checked })} />
              Require consent
            </label>
            <label style={{ display: "flex", gap: 6, alignItems: "center" }} title="Turn off only while fixing domain settings">
              <input type="checkbox" checked={website.enforce_origin} onChange={(e) => update.mutate({ enforce_origin: e.target.checked })} />
              Only accept events from these domains
            </label>
            <span style={{ display: "flex", gap: 6, alignItems: "center", flex: 1, minWidth: 260 }}>
              <span style={{ whiteSpace: "nowrap" }}>Also allowed:</span>
              <input className="form-input" style={{ padding: "4px 8px", fontSize: 12 }} value={extra}
                placeholder="other-domain.com (subdomains of the main domain are always allowed)"
                onChange={(e) => setExtra(e.target.value)} />
              <button className="btn btn-secondary btn-sm" disabled={update.isPending}
                onClick={() => update.mutate({ allowed_domains: extra.split(",").map((d) => d.trim()).filter(Boolean) })}>
                Save
              </button>
            </span>
          </div>
        )}
      </div>
    </Card>
  );
}
