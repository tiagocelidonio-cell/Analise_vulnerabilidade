import React, { useEffect, useState, useCallback } from "react";
import { api, getToken } from "./api.js";
import Dashboard from "./Dashboard.jsx";
import Login from "./Login.jsx";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_COLOR = {
  critical: "#7f1d1d", high: "#b91c1c", medium: "#c2410c",
  low: "#a16207", info: "#334155",
};

function Pill({ sev }) {
  return (
    <span className="pill" style={{ background: SEV_COLOR[sev] || "#334155" }}>
      {sev.toUpperCase()}
    </span>
  );
}

function NewEngagement({ onCreated }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    client_name: "", name: "", scope: "", authorized: false, authorized_by: "",
  });
  const [err, setErr] = useState("");

  async function submit(e) {
    e.preventDefault();
    setErr("");
    try {
      const body = {
        ...form,
        scope: form.scope.split("\n").map((s) => s.trim()).filter(Boolean),
      };
      const eng = await api.createEngagement(body);
      setForm({ client_name: "", name: "", scope: "", authorized: false, authorized_by: "" });
      setOpen(false);
      onCreated(eng);
    } catch (e) { setErr(e.message); }
  }

  if (!open)
    return <button className="btn block" onClick={() => setOpen(true)}>+ Novo cliente / engagement</button>;

  return (
    <form className="card" onSubmit={submit}>
      <h3>Novo engagement</h3>
      <input placeholder="Cliente" value={form.client_name}
        onChange={(e) => setForm({ ...form, client_name: e.target.value })} required />
      <input placeholder="Nome do trabalho (ex: Externo Q4)" value={form.name}
        onChange={(e) => setForm({ ...form, name: e.target.value })} required />
      <textarea placeholder="Escopo (um por linha): 10.0.0.0/24, example.com, 1.2.3.4"
        value={form.scope} rows={3}
        onChange={(e) => setForm({ ...form, scope: e.target.value })} />
      <input placeholder="Autorizado por (email/nome)" value={form.authorized_by}
        onChange={(e) => setForm({ ...form, authorized_by: e.target.value })} />
      <label className="check">
        <input type="checkbox" checked={form.authorized}
          onChange={(e) => setForm({ ...form, authorized: e.target.checked })} />
        Autorizo o scan deste escopo (obrigatorio)
      </label>
      {err && <div className="err">{err}</div>}
      <div className="row">
        <button className="btn primary" type="submit">Criar</button>
        <button className="btn" type="button" onClick={() => setOpen(false)}>Cancelar</button>
      </div>
    </form>
  );
}

function NewScan({ engagement, onStarted }) {
  const [form, setForm] = useState({ targets: "", ports: "", collectors: [] });
  const [err, setErr] = useState("");

  function toggleCollector(c) {
    setForm((f) => ({
      ...f,
      collectors: f.collectors.includes(c)
        ? f.collectors.filter((x) => x !== c)
        : [...f.collectors, c],
    }));
  }

  async function submit(e) {
    e.preventDefault();
    setErr("");
    try {
      const body = {
        targets: form.targets.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean),
        ports: form.ports.split(/[\s,]+/).map((s) => parseInt(s, 10)).filter((n) => !isNaN(n)),
        collectors: form.collectors,
      };
      const scan = await api.createScan(engagement.id, body);
      setForm({ targets: "", ports: "", collectors: [] });
      onStarted(scan);
    } catch (e) { setErr(e.message); }
  }

  return (
    <form className="card" onSubmit={submit}>
      <h3>Novo scan</h3>
      {!engagement.authorized && (
        <div className="err">Engagement nao autorizado — o scan sera bloqueado.</div>
      )}
      <input placeholder="Alvos (separados por espaco/virgula)" value={form.targets}
        onChange={(e) => setForm({ ...form, targets: e.target.value })} required />
      <input placeholder="Portas (vazio = padrao)" value={form.ports}
        onChange={(e) => setForm({ ...form, ports: e.target.value })} />
      <div className="row collectors">
        {["port_scan", "http_probe", "subdomain_enum", "wayback", "google_dorks"].map((c) => (
          <label key={c} className="check">
            <input type="checkbox" checked={form.collectors.includes(c)}
              onChange={() => toggleCollector(c)} />
            {c}
          </label>
        ))}
        <span className="muted">(nenhum marcado = port_scan + http_probe)</span>
      </div>
      <p className="muted" style={{ marginTop: "-2px" }}>
        Recon (subdomain_enum, wayback, google_dorks) usa o alvo como <b>domínio</b>
        {" "}(ex.: example.com).
      </p>
      {err && <div className="err">{err}</div>}
      <button className="btn primary" type="submit">Disparar scan</button>
    </form>
  );
}

function FindingRow({ f }) {
  const [open, setOpen] = useState(false);
  const a = f.ai_assessment || {};
  return (
    <>
      <tr className="click" onClick={() => setOpen(!open)}>
        <td><Pill sev={f.severity} /></td>
        <td>{f.target}{f.port ? `:${f.port}` : ""}</td>
        <td>{f.title}</td>
        <td>{f.cvss?.toFixed(1) ?? "-"}</td>
        <td>{f.epss?.toFixed(2) ?? "-"}</td>
        <td>{f.in_kev ? "SIM" : "-"}</td>
        <td>{Math.round(f.confidence * 100)}%</td>
      </tr>
      {open && (
        <tr className="detail">
          <td colSpan={7}>
            {f.cve_ids?.length > 0 && <p><b>CVEs:</b> {f.cve_ids.join(", ")}</p>}
            <p><b>Risco:</b> {a.risk_summary || "-"}</p>
            <p><b>Explorabilidade:</b> {a.exploitability || "-"}</p>
            <p><b>Recomendacao:</b> {a.recommendation || "-"}</p>
            <p className="muted">Avaliado por: {a.model || "stub"}</p>
            {f.evidences?.map((ev) => (
              <div key={ev.id}>
                <p className="muted">Evidencia ({ev.kind}):</p>
                <pre className="evi">{ev.content || ev.s3_key || "(sem conteudo)"}</pre>
              </div>
            ))}
          </td>
        </tr>
      )}
    </>
  );
}

function EngagementView({ engagement }) {
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);

  const refresh = useCallback(async () => {
    const [s, f] = await Promise.all([
      api.listScans(engagement.id),
      api.listFindings(engagement.id),
    ]);
    setScans(s);
    setFindings(f);
  }, [engagement.id]);

  useEffect(() => { refresh(); }, [refresh]);

  // Poll enquanto houver scan rodando.
  useEffect(() => {
    const running = scans.some((s) => s.status === "queued" || s.status === "running");
    if (!running) return;
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [scans, refresh]);

  const counts = SEV_ORDER.map((s) => ({
    sev: s, n: findings.filter((f) => f.severity === s).length,
  }));

  const [tab, setTab] = useState("dashboard");

  return (
    <div>
      <div className="tabs">
        <button className={`tab ${tab === "dashboard" ? "active" : ""}`}
          onClick={() => setTab("dashboard")}>Dashboard</button>
        <button className={`tab ${tab === "ops" ? "active" : ""}`}
          onClick={() => setTab("ops")}>Operação</button>
      </div>

      {tab === "dashboard" ? (
        <Dashboard engagement={engagement} />
      ) : (
      <>
      <div className="head">
        <div>
          <h2>{engagement.name}</h2>
          <p className="muted">{engagement.client_name} · {engagement.scope.join(", ") || "sem escopo"}</p>
        </div>
        <div className="row">
          <a className="btn" href={api.reportHtmlUrl(engagement.id)} target="_blank" rel="noreferrer">Preview</a>
          <a className="btn primary" href={api.reportPdfUrl(engagement.id)}>Baixar PDF</a>
        </div>
      </div>

      <div className="kpis">
        {counts.map((c) => (
          <div key={c.sev} className="kpi">
            <div className="n" style={{ color: SEV_COLOR[c.sev] }}>{c.n}</div>
            <div className="l">{c.sev.toUpperCase()}</div>
          </div>
        ))}
      </div>

      <NewScan engagement={engagement} onStarted={refresh} />

      <h3>Scans</h3>
      <table className="t">
        <thead><tr><th>Status</th><th>Alvos</th><th>Coletores</th><th>Erro</th></tr></thead>
        <tbody>
          {scans.map((s) => (
            <tr key={s.id}>
              <td><span className={`status ${s.status}`}>{s.status}</span></td>
              <td>{s.targets.join(", ")}</td>
              <td>{(s.collectors.length ? s.collectors : ["todos"]).join(", ")}</td>
              <td className="muted">{s.error || "-"}</td>
            </tr>
          ))}
          {scans.length === 0 && <tr><td colSpan={4} className="muted">Nenhum scan ainda.</td></tr>}
        </tbody>
      </table>

      <h3>Achados ({findings.length})</h3>
      <table className="t">
        <thead><tr><th>Sev</th><th>Alvo</th><th>Achado</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Conf.</th></tr></thead>
        <tbody>
          {findings.map((f) => <FindingRow key={f.id} f={f} />)}
          {findings.length === 0 && <tr><td colSpan={7} className="muted">Sem achados. Dispare um scan.</td></tr>}
        </tbody>
      </table>
      </>
      )}
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [engagements, setEngagements] = useState([]);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");

  // Verifica a sessao ao abrir.
  useEffect(() => {
    (async () => {
      if (getToken()) {
        try { setUser(await api.me()); } catch { /* token invalido */ }
      }
      setAuthChecked(true);
    })();
  }, []);

  const load = useCallback(async () => {
    try { setEngagements(await api.listEngagements()); }
    catch (e) { setError(e.message); }
  }, []);

  useEffect(() => { if (user) load(); }, [user, load]);

  function logout() {
    api.logout();
    setUser(null); setSelected(null); setEngagements([]);
  }

  if (!authChecked) return <div className="empty">Carregando…</div>;
  if (!user) return <Login onLogin={setUser} />;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">VulnScope</div>
        <div className="userbox">
          <div>
            <div className="uname">{user.name || user.email}</div>
            <div className="muted" style={{ fontSize: 11 }}>{user.role}</div>
          </div>
          <button className="btn" onClick={logout}>Sair</button>
        </div>
        <NewEngagement onCreated={(e) => { load(); setSelected(e); }} />
        <div className="list">
          {engagements.map((e) => (
            <button key={e.id}
              className={`eng ${selected?.id === e.id ? "active" : ""}`}
              onClick={() => setSelected(e)}>
              <div className="ename">{e.name}</div>
              <div className="eclient muted">{e.client_name}{e.authorized ? "" : " · nao autorizado"}</div>
            </button>
          ))}
          {engagements.length === 0 && <p className="muted">Nenhum engagement.</p>}
        </div>
        {error && <div className="err">{error}</div>}
        <div className="api muted">API: {api.base}</div>
      </aside>
      <main className="main">
        {selected
          ? <EngagementView key={selected.id} engagement={selected} />
          : <div className="empty">Selecione ou crie um engagement.</div>}
      </main>
    </div>
  );
}
