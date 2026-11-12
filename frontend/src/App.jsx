import React, { useEffect, useState, useCallback } from "react";
import { api, getToken } from "./api.js";
import { branding } from "./branding.js";
import Dashboard from "./Dashboard.jsx";
import Playbook from "./Playbook.jsx";
import ToolCatalog from "./ToolCatalog.jsx";
import Assets from "./Assets.jsx";
import Overview from "./Overview.jsx";
import Admin from "./Admin.jsx";
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
    allow_intrusive: false,
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
      setForm({ client_name: "", name: "", scope: "", authorized: false,
        authorized_by: "", allow_intrusive: false });
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
      <label className="check">
        <input type="checkbox" checked={form.allow_intrusive}
          onChange={(e) => setForm({ ...form, allow_intrusive: e.target.checked })} />
        Permitir sondas intrusivas (ativas, não-destrutivas) — opt-in
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

function ScopeEditor({ engagement, onSaved, onCancel }) {
  const [list, setList] = useState([...(engagement.scope || [])]);
  const [entry, setEntry] = useState("");
  const [err, setErr] = useState("");

  function add() {
    const v = entry.trim().toLowerCase();
    if (v && !list.includes(v)) setList([...list, v]);
    setEntry("");
  }
  async function save() {
    try {
      const upd = await api.updateEngagement(engagement.id, { scope: list });
      onSaved(upd);
    } catch (e) { setErr(e.message); }
  }

  return (
    <div className="card">
      <h3>Editar escopo (IPs, CIDRs, domínios, hosts)</h3>
      <div className="scopeList">
        {list.map((s) => (
          <span key={s} className="chip">
            {s}
            <button type="button" className="chipx"
              onClick={() => setList(list.filter((x) => x !== s))}>×</button>
          </span>
        ))}
        {list.length === 0 && <span className="muted">Escopo vazio.</span>}
      </div>
      <div className="row">
        <input placeholder="Adicionar (ex: 10.0.0.0/24, example.com, 1.2.3.4)"
          value={entry}
          onChange={(e) => setEntry(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(); } }} />
        <button className="btn" type="button" onClick={add}>Adicionar</button>
      </div>
      {err && <div className="err">{err}</div>}
      <div className="row">
        <button className="btn primary" type="button" onClick={save}>Salvar escopo</button>
        <button className="btn" type="button" onClick={onCancel}>Cancelar</button>
      </div>
    </div>
  );
}

function EngagementView({ engagement, onDeleted, onUpdated }) {
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [editingScope, setEditingScope] = useState(false);
  const [showAdvScan, setShowAdvScan] = useState(false);
  const [sevFilter, setSevFilter] = useState("");

  async function removeEngagement() {
    if (!window.confirm(
      `Excluir o cliente "${engagement.client_name}" e TODOS os seus scans, `
      + `achados e evidências? Esta ação não pode ser desfeita.`
    )) return;
    await api.deleteEngagement(engagement.id);
    onDeleted();
  }

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

  const [tab, setTab] = useState("playbook");

  return (
    <div>
      <div className="tabs">
        <button className={`tab ${tab === "playbook" ? "active" : ""}`}
          onClick={() => setTab("playbook")}>Playbook</button>
        <button className={`tab ${tab === "tools" ? "active" : ""}`}
          onClick={() => setTab("tools")}>Nova varredura</button>
        <button className={`tab ${tab === "assets" ? "active" : ""}`}
          onClick={() => setTab("assets")}>Ativos</button>
        <button className={`tab ${tab === "ops" ? "active" : ""}`}
          onClick={() => setTab("ops")}>Achados</button>
        <button className={`tab ${tab === "dashboard" ? "active" : ""}`}
          onClick={() => setTab("dashboard")}>Dashboard</button>
      </div>

      {tab === "playbook" && <Playbook engagement={engagement} />}
      {tab === "tools" && <ToolCatalog engagement={engagement}
        onUpdated={onUpdated} onRan={() => setTab("ops")} />}
      {tab === "assets" && <Assets engagement={engagement} onUpdated={onUpdated} />}
      {tab === "dashboard" && <Dashboard engagement={engagement} />}
      {tab === "ops" && (
      <>
      <div className="head">
        <div>
          <h2>{engagement.name}</h2>
          <p className="muted">{engagement.client_name} · {engagement.scope.join(", ") || "sem escopo"}</p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => setEditingScope(!editingScope)}>Editar escopo</button>
          <button className="btn danger" onClick={removeEngagement}>Excluir cliente</button>
        </div>
      </div>

      {editingScope && (
        <ScopeEditor engagement={engagement}
          onSaved={(upd) => { setEditingScope(false); onUpdated(upd); }}
          onCancel={() => setEditingScope(false)} />
      )}

      <p className="muted" style={{ fontSize: 13 }}>
        Os scans são disparados pelo <b>Playbook</b>. Aqui você acompanha o
        progresso e vê todos os achados.
      </p>

      <h3>Scans</h3>
      <table className="t">
        <thead><tr><th>Status</th><th>Progresso</th><th>Alvos</th><th>Resumo</th></tr></thead>
        <tbody>
          {scans.map((s) => (
            <tr key={s.id}>
              <td><span className={`status ${s.status}`}>{s.status}</span></td>
              <td style={{ minWidth: 160 }}>
                {s.status === "completed" ? (
                  <span className="muted">concluído</span>
                ) : s.status === "failed" ? (
                  <span className="muted" title={s.error || ""}>falhou: {(s.error || "").slice(0, 40)}</span>
                ) : (
                  <>
                    <div className="bartrack"><div className="barfill"
                      style={{ width: `${s.progress || 0}%`, background: "var(--accent)" }} /></div>
                    <span className="muted" style={{ fontSize: 11 }}>{s.progress || 0}% · {s.phase || "na fila"}</span>
                  </>
                )}
              </td>
              <td>{s.targets.join(", ")}</td>
              <td>{s.summary || `${s.findings_count || 0} achados`}</td>
            </tr>
          ))}
          {scans.length === 0 && <tr><td colSpan={4} className="muted">Nenhum scan ainda.</td></tr>}
        </tbody>
      </table>

      <div className="row" style={{ justifyContent: "space-between", alignItems: "center", marginTop: 8 }}>
        <h3 style={{ margin: 0 }}>Achados ({findings.length})</h3>
        <div className="row" style={{ gap: 4 }}>
          {["", "critical", "high", "medium", "low", "info"].map((s) => (
            <button key={s || "all"}
              className={`chip ${sevFilter === s ? "active" : ""}`}
              onClick={() => setSevFilter(s)}>{s ? s.toUpperCase() : "TODOS"}</button>
          ))}
        </div>
      </div>
      <table className="t">
        <thead><tr><th>Sev</th><th>Alvo</th><th>Achado</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Conf.</th></tr></thead>
        <tbody>
          {findings.filter((f) => !sevFilter || f.severity === sevFilter)
            .map((f) => <FindingRow key={f.id} f={f} />)}
          {findings.length === 0 && <tr><td colSpan={7} className="muted">
            Sem achados ainda. Vá ao <b>Playbook</b> e rode o reconhecimento e a varredura.</td></tr>}
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
  const [view, setView] = useState("overview"); // overview | client | admin
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
        <div className="brand">
          <img src={branding.logo} alt="logo" className="brandLogo" />
          {branding.appName}
        </div>
        <div className="userbox">
          <div>
            <div className="uname">{user.name || user.email}</div>
            <div className="muted" style={{ fontSize: 11 }}>{user.role}</div>
          </div>
          <button className="btn" onClick={logout}>Sair</button>
        </div>
        <nav className="nav">
          <button className={`navbtn ${view === "overview" ? "active" : ""}`}
            onClick={() => { setView("overview"); setSelected(null); }}>Visão geral</button>
          {user.role === "admin" && (
            <button className={`navbtn ${view === "admin" ? "active" : ""}`}
              onClick={() => { setView("admin"); setSelected(null); }}>Usuários</button>
          )}
        </nav>
        <NewEngagement onCreated={(e) => { load(); setSelected(e); setView("client"); }} />
        <div className="list">
          {engagements.map((e) => (
            <button key={e.id}
              className={`eng ${selected?.id === e.id && view === "client" ? "active" : ""}`}
              onClick={() => { setSelected(e); setView("client"); }}>
              <div className="ename">{e.name}</div>
              <div className="eclient muted">{e.client_name}{e.authorized ? "" : " · nao autorizado"}</div>
            </button>
          ))}
          {engagements.length === 0 && <p className="muted">Nenhum cliente.</p>}
        </div>
        {error && <div className="err">{error}</div>}
        <div className="api muted">API: {api.base}</div>
      </aside>
      <main className="main">
        {view === "overview" && <Overview />}
        {view === "admin" && <Admin me={user} />}
        {view === "client" && selected && (
          <EngagementView key={selected.id} engagement={selected}
            onDeleted={() => { setSelected(null); setView("overview"); load(); }}
            onUpdated={(e) => { setSelected(e); load(); }} />
        )}
        {view === "client" && !selected && <div className="empty">Selecione um cliente.</div>}
      </main>
    </div>
  );
}
