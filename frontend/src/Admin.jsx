import React, { useEffect, useState, useCallback } from "react";
import { api } from "./api.js";
import { applyConfig, branding, fmtDateTime, SKINS } from "./branding.js";
import CveBase from "./CveBase.jsx";
import CveBrowser from "./CveBrowser.jsx";
import Integrations from "./Integrations.jsx";

const METHOD_COLOR = { POST: "#15803d", PUT: "#1c476b", PATCH: "#b45309", DELETE: "#b91c1c" };

function Audit() {
  const [rows, setRows] = useState(null);
  const [err, setErr] = useState("");
  const [cfg, setCfg] = useState(null);
  const [msg, setMsg] = useState("");
  const load = useCallback(async () => {
    try { setRows(await api.getAudit()); } catch (e) { setErr(e.message); }
    try { setCfg(await api.auditConfig()); } catch { /* ignore */ }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function toggle() {
    try {
      const r = await api.auditSetEnabled(!cfg.enabled);
      setCfg({ ...cfg, enabled: r.enabled });
      setMsg(r.enabled ? "Auditoria habilitada." : "Auditoria DESABILITADA — novas ações não serão registradas.");
    } catch (e) { setMsg(`Falha: ${e.message}`); }
  }
  async function purge() {
    if (!window.confirm("Expurgar TODA a trilha de auditoria? Esta ação não pode ser desfeita.")) return;
    try {
      const r = await api.auditPurge();
      setMsg(`Expurgado: ${r.deleted} registro(s) removido(s).`);
      load();
    } catch (e) { setMsg(`Falha: ${e.message}`); }
  }

  if (err) return <div className="err">{err}</div>;
  if (!rows) return <div className="muted">Carregando…</div>;
  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
        <p className="muted" style={{ marginTop: 0 }}>
          Últimas ações de alteração no sistema.
          {cfg && <> · estado: <b style={{ color: cfg.enabled ? "#15803d" : "#b91c1c" }}>
            {cfg.enabled ? "habilitada" : "desabilitada"}</b>
            {typeof cfg.count === "number" && ` · ${cfg.count} registro(s)`}</>}
        </p>
        <div className="row" style={{ gap: 6 }}>
          {cfg && <button className={`btn ${cfg.enabled ? "" : "primary"}`} onClick={toggle}>
            {cfg.enabled ? "Desabilitar auditoria" : "Habilitar auditoria"}</button>}
          <button className="btn danger" onClick={purge}>Expurgar log</button>
          <button className="btn" onClick={load}>Atualizar</button>
        </div>
      </div>
      {msg && <div className="info" style={{ fontSize: 12, marginBottom: 8 }}>{msg}</div>}
      <table className="t">
        <thead><tr><th>Quando</th><th>Usuário</th><th>Ação</th><th>Recurso</th><th>Resultado</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td className="muted" style={{ fontSize: 12, whiteSpace: "nowrap" }}>{fmtDateTime(r.created_at)}</td>
              <td>{r.user}</td>
              <td><span className="pill" style={{ background: METHOD_COLOR[r.method] || "#334155", fontSize: 10 }}>{r.method}</span></td>
              <td className="muted" style={{ fontSize: 12, wordBreak: "break-all" }}>{r.path}</td>
              <td>{r.status}</td>
            </tr>
          ))}
          {rows.length === 0 && <tr><td colSpan={5} className="muted">Sem registros.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

const TIMEZONES = [
  "America/Sao_Paulo", "America/Manaus", "America/Belem", "America/Fortaleza",
  "America/Recife", "America/Bahia", "America/Cuiaba", "America/Campo_Grande",
  "America/Noronha", "America/New_York", "America/Chicago", "America/Los_Angeles",
  "Europe/Lisbon", "Europe/London", "Europe/Madrid", "UTC",
];
const COLOR_FIELDS = [
  ["accent", "Destaque (verde/ação)"], ["bg", "Fundo"], ["panel", "Painel lateral"],
  ["card", "Cartão"], ["line", "Bordas"], ["text", "Texto"], ["muted", "Texto suave"],
  ["accent2", "Secundária"],
];
const FONT_SUGGESTIONS = [
  "'Plus Jakarta Sans', system-ui, sans-serif",
  "'Inter', system-ui, sans-serif",
  "system-ui, -apple-system, sans-serif",
  "Arial, Helvetica, sans-serif",
  "Georgia, 'Times New Roman', serif",
];
const HEADING_SUGGESTIONS = [
  "'IBM Plex Mono', ui-monospace, monospace",
  "'Plus Jakarta Sans', system-ui, sans-serif",
  "'Space Grotesk', system-ui, sans-serif",
  "Georgia, serif",
];

/* ---------------- Usuários ---------------- */
function Users({ me }) {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ email: "", name: "", password: "", role: "analyst" });
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");

  const load = useCallback(async () => {
    try { setUsers(await api.listUsers()); } catch (e) { setErr(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function create(e) {
    e.preventDefault(); setErr(""); setMsg("");
    try {
      await api.createUser(form);
      setForm({ email: "", name: "", password: "", role: "analyst" });
      setMsg("Usuário criado."); await load();
    } catch (e) { setErr(e.message); }
  }
  async function remove(u) {
    if (!window.confirm(`Excluir o usuário ${u.email}?`)) return;
    try { await api.deleteUser(u.id); await load(); } catch (e) { setErr(e.message); }
  }
  async function toggleRole(u) {
    const role = u.role === "admin" ? "analyst" : "admin";
    try { await api.updateUser(u.id, { email: u.email, password: "", role }); await load(); }
    catch (e) { setErr(e.message); }
  }

  return (
    <div>
      <form className="card" onSubmit={create}>
        <h3>Novo usuário</h3>
        <div className="row">
          <input placeholder="E-mail" type="email" value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })} required />
          <input placeholder="Nome" value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </div>
        <div className="row">
          <input placeholder="Senha" type="password" value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })} required />
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="analyst">analyst (consultor)</option>
            <option value="admin">admin</option>
          </select>
          <button className="btn primary" type="submit">Criar</button>
        </div>
        {err && <div className="err">{err}</div>}
        {msg && <div className="info">{msg}</div>}
      </form>

      <table className="t">
        <thead><tr><th>E-mail</th><th>Nome</th><th>Papel</th><th>Ativo</th><th></th></tr></thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td>{u.email}{u.id === me.id && <span className="muted"> (você)</span>}</td>
              <td>{u.name || "—"}</td>
              <td><span className="pill" style={{ background: u.role === "admin" ? "#1f6feb" : "#334155" }}>{u.role}</span></td>
              <td>{u.is_active ? "sim" : "não"}</td>
              <td className="row">
                {u.id !== me.id && (
                  <>
                    <button className="btn" onClick={() => toggleRole(u)}>
                      {u.role === "admin" ? "→ analyst" : "→ admin"}
                    </button>
                    <button className="btn danger" onClick={() => remove(u)}>Excluir</button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ---------------- Config compartilhada ---------------- */
function useConfig() {
  const [cfg, setCfg] = useState(null);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  useEffect(() => { (async () => {
    try { setCfg(await api.getConfig()); } catch (e) { setErr(e.message); }
  })(); }, []);
  async function save(patch) {
    setMsg(""); setErr("");
    try {
      const saved = await api.updateConfig(patch);
      setCfg(saved); applyConfig(saved); setMsg("Salvo.");
    } catch (e) { setErr(e.message); }
  }
  return { cfg, setCfg, save, msg, err };
}

/* ---------------- Plataforma (nome + logo) ---------------- */
function Platform() {
  const { cfg, setCfg, save, msg, err } = useConfig();
  if (!cfg) return <div className="muted">Carregando…</div>;
  function onLogo(e) {
    const f = e.target.files?.[0]; if (!f) return;
    if (f.size > 500 * 1024) { alert("Logo muito grande (máx. 500 KB)."); return; }
    const reader = new FileReader();
    reader.onload = () => setCfg({ ...cfg, logo: reader.result });
    reader.readAsDataURL(f);
  }
  return (
    <div className="card" style={{ maxWidth: 560 }}>
      <h3>Nome e logotipo</h3>
      <label className="muted" style={{ fontSize: 12 }}>Nome da plataforma</label>
      <input value={cfg.platform_name || ""} onChange={(e) => setCfg({ ...cfg, platform_name: e.target.value })} />
      <label className="muted" style={{ fontSize: 12, marginTop: 10 }}>Logotipo</label>
      <div className="row" style={{ alignItems: "center", gap: 12 }}>
        <div style={{ width: 120, height: 48, background: "#000", border: "1px solid var(--line)",
          borderRadius: 6, display: "flex", alignItems: "center", justifyContent: "center", overflow: "hidden" }}>
          <img src={cfg.logo || "/logo.svg"} alt="logo" style={{ maxWidth: "100%", maxHeight: "100%" }} />
        </div>
        <label className="btn" style={{ cursor: "pointer" }}>
          Enviar logo (PNG/SVG)
          <input type="file" accept="image/*" style={{ display: "none" }} onChange={onLogo} />
        </label>
        {cfg.logo && <button className="btn" onClick={() => setCfg({ ...cfg, logo: "" })}>Remover</button>}
      </div>
      <div className="row" style={{ marginTop: 12 }}>
        <button className="btn primary" onClick={() => save({ platform_name: cfg.platform_name, logo: cfg.logo || "" })}>Salvar</button>
      </div>
      {msg && <div className="info">{msg}</div>}
      {err && <div className="err">{err}</div>}
    </div>
  );
}

/* ---------------- Identidade visual (cores + fontes) ---------------- */
function Identity() {
  const { cfg, setCfg, save, msg, err } = useConfig();
  if (!cfg) return <div className="muted">Carregando…</div>;
  const colors = { ...branding.colors, ...(cfg.colors || {}) };
  const setColor = (k, v) => setCfg({ ...cfg, colors: { ...(cfg.colors || {}), [k]: v } });
  // Pre-visualiza ao vivo.
  const preview = () => applyConfig({ ...cfg, colors });
  const applySkin = (sk) => {
    const next = { ...cfg, colors: { ...SKINS[sk].colors } };
    setCfg(next);
    applyConfig(next);  // pré-visualiza na hora
  };
  return (
    <div className="card" style={{ maxWidth: 640 }}>
      <h3>Tema (skin)</h3>
      <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
        Escolha um tema pronto (contraste texto/fundo garantido) e, se quiser, ajuste as cores abaixo.
      </p>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 14 }}>
        {Object.entries(SKINS).map(([k, sk]) => (
          <button key={k} className="btn" style={{ padding: "6px 10px", display: "flex", gap: 8, alignItems: "center" }}
            onClick={() => applySkin(k)} title={sk.name}>
            <span style={{ display: "flex", gap: 2 }}>
              {["bg", "card", "text", "accent"].map((c) => (
                <span key={c} style={{ width: 12, height: 12, borderRadius: 3, background: sk.colors[c], border: "1px solid rgba(128,128,128,.4)" }} />
              ))}
            </span>
            {sk.name}
          </button>
        ))}
      </div>
      <h3>Cores</h3>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
        {COLOR_FIELDS.map(([k, label]) => (
          <div key={k} className="row" style={{ gap: 8, alignItems: "center" }}>
            <input type="color" value={colors[k] || "#000000"} style={{ width: 42, height: 32, padding: 2 }}
              onChange={(e) => { setColor(k, e.target.value); }} onBlur={preview} />
            <input value={colors[k] || ""} onChange={(e) => setColor(k, e.target.value)} onBlur={preview}
              style={{ width: 100 }} />
            <span className="muted" style={{ fontSize: 12 }}>{label}</span>
          </div>
        ))}
      </div>

      <h3 style={{ marginTop: 16 }}>Fontes</h3>
      <label className="muted" style={{ fontSize: 12 }}>Fonte do corpo</label>
      <input list="fonts" value={cfg.font || ""} onChange={(e) => setCfg({ ...cfg, font: e.target.value })} />
      <datalist id="fonts">{FONT_SUGGESTIONS.map((f) => <option key={f} value={f} />)}</datalist>
      <label className="muted" style={{ fontSize: 12, marginTop: 8 }}>Fonte dos títulos</label>
      <input list="hfonts" value={cfg.heading_font || ""} onChange={(e) => setCfg({ ...cfg, heading_font: e.target.value })} />
      <datalist id="hfonts">{HEADING_SUGGESTIONS.map((f) => <option key={f} value={f} />)}</datalist>

      <div className="row" style={{ marginTop: 14, gap: 8 }}>
        <button className="btn" onClick={preview}>Pré-visualizar</button>
        <button className="btn primary" onClick={() => save({ colors, font: cfg.font || "", heading_font: cfg.heading_font || "" })}>Salvar</button>
      </div>
      <p className="muted" style={{ fontSize: 11 }}>As fontes precisam estar disponíveis (sistema ou carregadas). Dica: comece pelo "Destaque" (cor dos botões de ação).</p>
      {msg && <div className="info">{msg}</div>}
      {err && <div className="err">{err}</div>}
    </div>
  );
}

/* ---------------- Data / hora / fuso ---------------- */
function Clock() {
  const { cfg, setCfg, save, msg, err } = useConfig();
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);
  if (!cfg) return <div className="muted">Carregando…</div>;
  let preview = "-";
  try { preview = new Date(now).toLocaleString("pt-BR", { timeZone: cfg.timezone }); } catch { /* */ }
  return (
    <div className="card" style={{ maxWidth: 520 }}>
      <h3>Data, hora e fuso horário</h3>
      <label className="muted" style={{ fontSize: 12 }}>Fuso horário (todas as datas do sistema usam este fuso)</label>
      <input list="tzs" value={cfg.timezone || ""} onChange={(e) => setCfg({ ...cfg, timezone: e.target.value })} />
      <datalist id="tzs">{TIMEZONES.map((t) => <option key={t} value={t} />)}</datalist>
      <p style={{ marginTop: 10 }}>Agora, nesse fuso: <b>{preview}</b></p>
      <div className="row" style={{ marginTop: 8 }}>
        <button className="btn primary" onClick={() => save({ timezone: cfg.timezone })}>Salvar</button>
      </div>
      {msg && <div className="info">{msg}</div>}
      {err && <div className="err">{err}</div>}
    </div>
  );
}

const SECTIONS = [
  { k: "users", label: "Usuários" },
  { k: "integrations", label: "Integrações / API Keys" },
  { k: "cve", label: "Base de CVEs" },
  { k: "cvesearch", label: "Consultar CVEs" },
  { k: "platform", label: "Plataforma" },
  { k: "identity", label: "Identidade visual" },
  { k: "clock", label: "Data / hora" },
  { k: "audit", label: "Auditoria" },
];

export default function Admin({ me }) {
  const [sec, setSec] = useState("users");
  return (
    <div>
      <div className="head"><div>
        <h2>Administração do sistema</h2>
        <p className="muted">Fuso atual: {branding.timezone} · {fmtDateTime(new Date().toISOString())}</p>
      </div></div>
      <div className="tabs">
        {SECTIONS.map((s) => (
          <button key={s.k} className={`tab ${sec === s.k ? "active" : ""}`}
            onClick={() => setSec(s.k)}>{s.label}</button>
        ))}
      </div>
      {sec === "users" && <Users me={me} />}
      {sec === "integrations" && <Integrations />}
      {sec === "cve" && <CveBase />}
      {sec === "cvesearch" && <CveBrowser />}
      {sec === "platform" && <Platform />}
      {sec === "identity" && <Identity />}
      {sec === "clock" && <Clock />}
      {sec === "audit" && <Audit />}
    </div>
  );
}
