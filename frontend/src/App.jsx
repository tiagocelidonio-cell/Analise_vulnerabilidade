import React, { useEffect, useState, useCallback } from "react";
import { api, getToken } from "./api.js";
import { branding, onBrandingChange, fmtDate, fmtDateTime } from "./branding.js";
import Dashboard from "./Dashboard.jsx";
import ToolCatalog from "./ToolCatalog.jsx";
import Assets from "./Assets.jsx";
import Documents from "./Documents.jsx";
import Topology from "./Topology.jsx";
import ToolForm from "./ToolForm.jsx";
import { FLAT_TOOLS } from "./tools.js";
import { downloadCsv } from "./csv.js";
import Overview from "./Overview.jsx";
import ScanConsole from "./ScanConsole.jsx";
import Admin from "./Admin.jsx";
import Reports from "./Reports.jsx";
import Profile from "./Profile.jsx";
import Login from "./Login.jsx";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const ENGAGEMENT_TYPES = [
  { v: "vuln_analysis", l: "Análise de Vulnerabilidades" },
  { v: "pentest_blackbox", l: "Pentest Blackbox" },
  { v: "pentest_graybox", l: "Pentest Graybox" },
  { v: "pentest_whitebox", l: "Pentest Whitebox" },
  { v: "pentest_internal", l: "Pentest Interno / Rede" },
  { v: "wireless", l: "Wireless" },
  { v: "red_team", l: "Red Team" },
];
const ENG_TYPE_LABEL = Object.fromEntries(ENGAGEMENT_TYPES.map((t) => [t.v, t.l]));
const FINDING_STATUS = [
  { v: "open", l: "Aberto", c: "#334155" },
  { v: "confirmed", l: "Confirmado", c: "#b45309" },
  { v: "in_progress", l: "Em correção", c: "#1c476b" },
  { v: "fixed", l: "Corrigido", c: "#15803d" },
  { v: "accepted", l: "Risco aceito", c: "#6b7280" },
  { v: "false_positive", l: "Falso-positivo", c: "#475569" },
];
const FSTATUS = Object.fromEntries(FINDING_STATUS.map((s) => [s.v, s]));
const STATUS_PT = {
  queued: "na fila", running: "em andamento", completed: "concluído",
  failed: "falhou", cancelled: "cancelado", paused: "pausado",
};
const COLLECTOR_LABEL = {
  port_scan: "Descoberta de Portas", http_probe: "Reconhecimento Web",
  web_content: "Conteúdo Exposto", web_vuln: "Verificação de Vulnerabilidades",
  subdomain_enum: "Enumeração de Ativos", wayback: "Arquivos Históricos",
  google_dorks: "Busca por Exposições", validate: "Validação (SAFE)",
  validate_intrusive: "Validação avançada", tech_detect: "Tecnologias",
  osint: "OSINT", screenshot: "Captura de Tela", leaks: "Vazamentos",
};
function agoText(ts) {
  if (!ts) return null;
  const s = Math.max(0, Math.round((Date.now() - new Date(ts).getTime()) / 1000));
  if (s < 60) return `há ${s}s`;
  if (s < 3600) return `há ${Math.floor(s / 60)}min`;
  return `há ${Math.floor(s / 3600)}h`;
}
function secsSince(ts) {
  if (!ts) return null;
  return (Date.now() - new Date(ts).getTime()) / 1000;
}
function scanTypeLabel(collectors) {
  if (!collectors || !collectors.length) return "padrão";
  return collectors.map((c) => COLLECTOR_LABEL[c] || c).join(" + ");
}
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
    client_name: "", name: "", engagement_type: "vuln_analysis", scope: "",
    authorized: false, authorized_by: "", allow_intrusive: false,
    allow_exploitation: false, auto_recon: false,
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
      setForm({ client_name: "", name: "", engagement_type: "vuln_analysis", scope: "",
        authorized: false, authorized_by: "", allow_intrusive: false,
        allow_exploitation: false, auto_recon: false });
      setOpen(false);
      onCreated(eng);
    } catch (e) { setErr(e.message); }
  }

  if (!open)
    return <button className="btn block" onClick={() => setOpen(true)}>+ Adicionar outro cliente</button>;

  return (
    <form className="card" onSubmit={submit} autoComplete="off">
      <h3>Novo engagement</h3>
      {/* input isca invisivel: absorve o autofill do navegador */}
      <input type="text" name="fakeusernameremembered" style={{ display: "none" }} />
      <input placeholder="Cliente" value={form.client_name} name="eng_client"
        autoComplete="off" autoCorrect="off" spellCheck="false"
        onChange={(e) => setForm({ ...form, client_name: e.target.value })} required />
      <input placeholder="Nome do trabalho (ex: Externo Q4)" value={form.name} name="eng_name"
        autoComplete="off"
        onChange={(e) => setForm({ ...form, name: e.target.value })} required />
      <label className="muted" style={{ fontSize: 12 }}>Modalidade</label>
      <select value={form.engagement_type}
        onChange={(e) => setForm({ ...form, engagement_type: e.target.value })}>
        {ENGAGEMENT_TYPES.map((t) => <option key={t.v} value={t.v}>{t.l}</option>)}
      </select>
      <textarea placeholder="Escopo (um por linha): 10.0.0.0/24, example.com, 1.2.3.4"
        value={form.scope} rows={3} autoComplete="off"
        onChange={(e) => setForm({ ...form, scope: e.target.value })} />
      <input placeholder="Autorizado por (email/nome)" value={form.authorized_by} name="eng_auth_by"
        autoComplete="off"
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
      <label className="check">
        <input type="checkbox" checked={form.allow_exploitation}
          onChange={(e) => setForm({ ...form, allow_exploitation: e.target.checked })} />
        Permitir <b>exploração</b> (operador confirma cada passo; requer autorização) — opt-in
      </label>
      <label className="check">
        <input type="checkbox" checked={form.auto_recon}
          onChange={(e) => setForm({ ...form, auto_recon: e.target.checked })} />
        <b>Recon automático</b> (ao achar subdomínios, varre-os sozinho: portas + web + tecnologias) — opt-in
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

// Classificacao FUNCIONAL dos achados por tipo (para agrupar na aba Achados).
const TYPE_ORDER = ["vuln", "ports", "web", "tech", "assets", "emails", "exposure", "ot", "leaks", "other"];
const TYPE_LABEL = {
  vuln: "Vulnerabilidades (CVE)",
  ports: "Portas abertas / serviços",
  web: "Serviços web / integrações",
  tech: "Tecnologias",
  assets: "Subdomínios e ativos",
  emails: "E-mails",
  exposure: "Exposições e configuração",
  ot: "OT / IoT",
  leaks: "Vazamentos",
  other: "Outras informações",
};
const TYPE_ICON = {
  vuln: "🛡️", ports: "🔌", web: "🌐", tech: "🧩", assets: "🗂️",
  emails: "✉️", exposure: "⚠️", ot: "🏭", leaks: "💧", other: "ℹ️",
};
const EMAIL_RE = /[^@\s]+@[^@\s]+\.[^@\s]+/; // endereço real (com @) — não casa hostname
function findingType(f) {
  const svc = (f.service || "").toLowerCase();
  const d = f.data || {};
  const title = f.title || "";
  if (d.ot) return "ot";
  if (svc === "exploit" || d.vuln) return "vuln";   // XSS/SQLi confirmados
  if ((f.cve_ids || []).length > 0) return "vuln";
  if (d.source === "leaks" || svc === "leak" || svc === "leaks" || d.breach) return "leaks";
  // E-mail: pelo DADO (data.email/emails) OU por um ENDEREÇO real no título
  // (tem @). Um host chamado "email.cliente.com" NAO casa (não tem @) — foi o
  // que antes jogava headers no grupo errado; e achados antigos sem data.email
  // agora caem certo pelo endereço no título "E-mail público: x@y.com".
  if (d.email || (Array.isArray(d.emails) && d.emails.length) || EMAIL_RE.test(title)) return "emails";
  if (svc === "tech") return "tech";
  if (svc === "subdomain" || svc === "host") return "assets";
  if (svc === "osint") {
    // OSINT de domínio/IP -> ativos; e-mail já foi tratado acima.
    return "assets";
  }
  if (svc === "tls" || d.weakness || d.path || d.listing) return "exposure";
  if (svc === "http" || svc === "https") return "web";
  if (f.port) return "ports";
  return "other";
}

function FindingRow({ f, selected, onToggle, onUpdated }) {
  const [open, setOpen] = useState(false);
  const [assignee, setAssignee] = useState(f.assignee || "");
  const [notes, setNotes] = useState(f.notes || "");
  const a = f.ai_assessment || {};
  const st = FSTATUS[f.status] || FSTATUS.open;

  async function setStatus(status) {
    try { await api.updateFinding(f.id, { status }); onUpdated && onUpdated(); }
    catch (e) { window.alert(e.message); }
  }
  async function saveMeta() {
    try { await api.updateFinding(f.id, { assignee, notes }); onUpdated && onUpdated(); }
    catch (e) { window.alert(e.message); }
  }

  return (
    <>
      <tr className="click" onClick={() => setOpen(!open)}>
        <td onClick={(e) => e.stopPropagation()}>
          <input type="checkbox" checked={selected} onChange={() => onToggle(f)} />
        </td>
        <td><Pill sev={f.severity} /></td>
        <td><span className="pill" style={{ background: st.c, fontSize: 10 }}>{st.l}</span></td>
        <td>{f.target}{f.port ? `:${f.port}` : ""}</td>
        <td>{f.title}
          {(f.data?.kind === "coverage") && <span className="persist"
            title="Relatório de cobertura: o que foi testado e o resultado. Não é uma vulnerabilidade."
            style={{ background: "#1c476b", color: "#dbeafe", borderColor: "#1c476b" }}>
            ℹ cobertura</span>}
          {(f.data?.kind === "api_surface") && <span className="persist"
            title="Superfície exposta mapeada (informativo)"
            style={{ background: "#1c476b", color: "#dbeafe", borderColor: "#1c476b" }}>
            ℹ superfície</span>}
          {f.times_seen > 1 && <span className="persist" title="encontrado em múltiplos scans">
            persiste ×{f.times_seen}</span>}
          {f.ai_assessment?.exploit_available && <span className="persist"
            title="existe exploit público conhecido" style={{ background: "#7f1d1d", color: "#fecaca", borderColor: "#7f1d1d" }}>
            exploit público</span>}
          {(f.data?.potential_cves?.length > 0) && <span className="persist"
            title="CVEs conhecidos do produto — versão não confirmada"
            style={{ background: "#78350f", color: "#fde68a", borderColor: "#78350f" }}>
            {f.data.potential_cves.length} CVE? potenciais</span>}
        </td>
        <td>{f.cvss?.toFixed(1) ?? "-"}</td>
        <td>{f.epss?.toFixed(2) ?? "-"}</td>
        <td>{f.in_kev ? "SIM" : "-"}</td>
        <td>{Math.round(f.confidence * 100)}%</td>
        <td className="muted" style={{ fontSize: 11, whiteSpace: "nowrap" }}>
          {fmtDate(f.created_at)}</td>
      </tr>
      {open && (
        <tr className="detail">
          <td colSpan={10}>
            <div className="card" style={{ margin: "0 0 10px", background: "var(--bg)" }}>
              <div className="row" style={{ gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                <b style={{ fontSize: 13 }}>Status:</b>
                {FINDING_STATUS.map((s) => (
                  <button key={s.v} className={`chip ${f.status === s.v ? "active" : ""}`}
                    onClick={() => setStatus(s.v)}>{s.l}</button>
                ))}
              </div>
              <div className="row" style={{ gap: 8, marginTop: 8, flexWrap: "wrap", alignItems: "center" }}>
                <input placeholder="Responsável" value={assignee} style={{ maxWidth: 200 }}
                  onChange={(e) => setAssignee(e.target.value)} />
                <input placeholder="Notas" value={notes}
                  onChange={(e) => setNotes(e.target.value)} />
                <button className="btn" onClick={saveMeta}>Salvar</button>
              </div>
            </div>
            <p className="muted">
              Visto {f.times_seen || 1}x
              {f.last_seen && ` · última vez ${new Date(f.last_seen).toLocaleString()}`}
              {f.times_seen > 1 && " — a vulnerabilidade PERSISTE após rescan."}
            </p>
            {f.cve_ids?.length > 0 && (
              <p><b>CVEs:</b>{" "}
                {f.cve_ids.map((c, i) => (
                  <span key={c}>
                    {i > 0 && ", "}
                    <a href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer"
                      style={{ color: "var(--accent)" }}>{c}</a>
                    {f.data?.cve_rule === c && (
                      <span className="pill" style={{ background: "#78350f", color: "#fde68a", fontSize: 9, marginLeft: 4 }} title={f.data?.cve_rule_reason || ""}>REGRA · versão não detectada</span>
                    )}
                  </span>
                ))}
              </p>
            )}
            {f.data?.cve_rule_reason && (
              <p className="warn" style={{ fontSize: 12 }}>
                ⚠ <b>Associação por regra:</b> {f.data.cve_rule_reason}
              </p>
            )}
            {f.data?.cve_lookup_error && (
              <p className="err" style={{ fontSize: 12 }}>
                ⚠ Correlação de CVE indisponível para <b>{f.data.cve_lookup_error}</b> (NVD
                inacessível ou limite de taxa) — pode haver CVE não detectado. Configure a
                <b> NVD_API_KEY</b> em Administração e rode de novo.
              </p>
            )}
            {f.data?.potential_cves?.length > 0 && (
              <div style={{ margin: "6px 0", padding: 8, border: "1px solid #78350f", borderRadius: 6 }}>
                <b style={{ color: "#f59e0b" }}>CVEs possíveis do produto ({f.data.potential_cves.length})</b>
                <div className="muted" style={{ fontSize: 11, margin: "2px 0 6px" }}>
                  O serviço <b>não revelou a versão</b>. O CVE de menor severidade foi associado
                  como linha de base (regra); estes são os <b>demais CVEs possíveis</b> do produto,
                  que só se confirmam com a versão exata. Rode o perfil <b>Completo</b> (detecção de
                  versão) para confirmar quais afetam este ativo.
                </div>
                <table className="t"><thead><tr><th>CVE</th><th>CVSS</th><th>Descrição</th></tr></thead>
                  <tbody>
                    {f.data.potential_cves.map((c) => (
                      <tr key={c.cve_id}>
                        <td><a href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`} target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>{c.cve_id}</a></td>
                        <td>{c.cvss != null ? c.cvss.toFixed(1) : "—"}</td>
                        <td style={{ fontSize: 12 }}>{(c.description || "").slice(0, 120)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {/* Detalhes técnicos estruturados (servem a qualquer tipo de achado). */}
            {(() => {
              const d = f.data || {};
              const rows = [];
              if (d.email) rows.push(["E-mail", d.email]);
              if (Array.isArray(d.emails) && d.emails.length) rows.push(["E-mails", d.emails.join(", ")]);
              if (d.server) rows.push(["Servidor", d.server]);
              if (d.banner && d.banner !== `Server: ${d.server || ""}`) rows.push(["Banner", d.banner]);
              if (d.product || d.version) rows.push(["Produto/versão", `${d.product || ""} ${d.version || ""}`.trim()]);
              if (Array.isArray(d.technologies) && d.technologies.length) rows.push(["Tecnologias", d.technologies.join(", ")]);
              if (d.url) rows.push(["URL", d.url]);
              if (d.path) rows.push(["Caminho", d.path]);
              if (d.status) rows.push(["HTTP", String(d.status)]);
              if (Array.isArray(d.ips) && d.ips.length) rows.push(["IPs", d.ips.join(", ")]);
              if (Array.isArray(d.domains) && d.domains.length) rows.push(["Domínios", d.domains.slice(0, 30).join(", ")]);
              if (d.via_port) rows.push(["Porta de resposta", String(d.via_port)]);
              if (d.cve_source) rows.push(["Fonte do CVE", d.cve_source]);
              if (!rows.length) return null;
              return (
                <div style={{ margin: "6px 0" }}>
                  <b style={{ fontSize: 13 }}>Detalhes técnicos</b>
                  <table className="t" style={{ marginTop: 4 }}>
                    <tbody>
                      {rows.map(([k, v]) => (
                        <tr key={k}><td style={{ width: 160, fontWeight: 600 }}>{k}</td>
                          <td style={{ wordBreak: "break-all" }}>{v}</td></tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              );
            })()}
            <p><b>Risco:</b> {a.risk_summary || "-"}</p>
            <p><b>Explorabilidade:</b> {a.exploitability || "-"}</p>
            <p><b>Recomendacao:</b> {a.recommendation || "-"}</p>
            {a.remediation && <p><b>Remediação (NVD):</b> {a.remediation}</p>}
            {a.cve_description && <p><b>Descrição do CVE:</b> {a.cve_description}</p>}
            {a.references?.length > 0 && (
              <p><b>Referências / patch:</b><br />
                {a.references.map((r) => (
                  <a key={r} href={r} target="_blank" rel="noreferrer"
                    style={{ color: "var(--accent)", display: "block", wordBreak: "break-all" }}>{r}</a>
                ))}
              </p>
            )}
            {f.data?.exploits?.length > 0 && (
              <div style={{ margin: "6px 0" }}>
                <b style={{ color: "#fca5a5" }}>⚠ Exploit(s) público(s) conhecido(s):</b>
                <ul style={{ margin: "4px 0", paddingLeft: 18 }}>
                  {f.data.exploits.map((ex, i) => (
                    <li key={i} style={{ fontSize: 12 }}>{ex.title}{ex.type ? ` (${ex.type})` : ""}</li>
                  ))}
                </ul>
              </div>
            )}
            <p className="muted">Avaliação: {
              a.model === "cobertura" ? "diagnóstico automático (cobertura do teste)"
              : a.model === "stub" || !a.model ? "heurística determinística (sem IA configurada)"
              : a.model}</p>
            {f.evidences?.map((ev) => (
              <div key={ev.id}>
                <p className="muted">Evidência ({ev.kind}):</p>
                {ev.kind === "screenshot" && ev.content?.startsWith("data:image")
                  ? <img src={ev.content} alt="screenshot"
                      style={{ maxWidth: "100%", border: "1px solid var(--line)", borderRadius: 6 }} />
                  : <pre className="evi">{ev.content || ev.s3_key || "(sem conteudo)"}</pre>}
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
  const [etype, setEtype] = useState(engagement.engagement_type || "vuln_analysis");
  const [expl, setExpl] = useState(!!engagement.allow_exploitation);
  const [autoRec, setAutoRec] = useState(!!engagement.auto_recon);
  const [err, setErr] = useState("");

  function add() {
    const v = entry.trim().toLowerCase();
    if (v && !list.includes(v)) setList([...list, v]);
    setEntry("");
  }
  async function save() {
    try {
      const upd = await api.updateEngagement(engagement.id, {
        scope: list, engagement_type: etype, allow_exploitation: expl, auto_recon: autoRec });
      onSaved(upd);
    } catch (e) { setErr(e.message); }
  }

  return (
    <div className="card">
      <h3>Editar engagement</h3>
      <label className="muted" style={{ fontSize: 12 }}>Modalidade</label>
      <select value={etype} onChange={(e) => setEtype(e.target.value)} style={{ marginBottom: 8 }}>
        {ENGAGEMENT_TYPES.map((t) => <option key={t.v} value={t.v}>{t.l}</option>)}
      </select>
      <label className="check" style={{ marginBottom: 8 }}>
        <input type="checkbox" checked={expl} onChange={(e) => setExpl(e.target.checked)} />
        Permitir exploração (operador confirma; requer autorização)
      </label>
      <label className="check" style={{ marginBottom: 8 }}>
        <input type="checkbox" checked={autoRec} onChange={(e) => setAutoRec(e.target.checked)} />
        Recon automático (varre subdomínios descobertos: portas + web + tecnologias)
      </label>
      <h3 style={{ marginTop: 6 }}>Escopo (IPs, CIDRs, domínios, hosts)</h3>
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
  const [sel, setSel] = useState(() => new Set());
  const [pickedTool, setPickedTool] = useState(null);
  const [pickOpen, setPickOpen] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [sortBy, setSortBy] = useState("sev");
  const [groupByType, setGroupByType] = useState(true);
  const [collapsedTypes, setCollapsedTypes] = useState(() => new Set());
  const [consoles, setConsoles] = useState(() => new Set());  // scans c/ terminal aberto
  const [reenriching, setReenriching] = useState(false);
  const toggleConsole = (id) => setConsoles((prev) => {
    const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n;
  });

  function toggleSel(f) {
    setSel((prev) => {
      const n = new Set(prev);
      n.has(f.id) ? n.delete(f.id) : n.add(f.id);
      return n;
    });
  }

  async function removeEngagement() {
    if (!window.confirm(
      `Excluir o cliente "${engagement.client_name}" e TODOS os seus scans, `
      + `achados e evidências? Esta ação não pode ser desfeita.`
    )) return;
    await api.deleteEngagement(engagement.id);
    onDeleted();
  }

  const [busyScan, setBusyScan] = useState(() => new Set());
  const markBusy = (id, on) => setBusyScan((p) => {
    const n = new Set(p); on ? n.add(id) : n.delete(id); return n;
  });
  async function cancelScan(id) {
    markBusy(id, true);
    try { await api.cancelScan(id); }
    catch (e) { window.alert(`Falha ao parar: ${e.message}`); }
    finally { markBusy(id, false); await refresh(); }
  }
  async function pauseScan(id) {
    markBusy(id, true);
    try { await api.pauseScan(id); }
    catch (e) { window.alert(`Falha ao pausar: ${e.message}`); }
    finally { markBusy(id, false); await refresh(); }
  }
  async function resumeScan(id) {
    markBusy(id, true);
    try { await api.resumeScan(id); }
    catch (e) { window.alert(`Falha ao retomar: ${e.message}`); }
    finally { markBusy(id, false); await refresh(); }
  }
  async function deleteScan(id) {
    if (!window.confirm("Excluir este scan do histórico?")) return;
    // Segunda pergunta: apagar também os achados deste scan?
    const delFindings = window.confirm(
      "Excluir TAMBÉM os achados encontrados por este scan?\n\n"
      + "OK = excluir os achados\nCancelar = manter os achados");
    markBusy(id, true);
    try { await api.deleteScan(id, delFindings); }
    catch (e) { window.alert(`Falha ao excluir: ${e.message}`); }
    finally { markBusy(id, false); await refresh(); }
  }
  async function deleteSelectedFindings() {
    const ids = [...sel];
    if (!ids.length) return;
    if (!window.confirm(`Excluir ${ids.length} achado(s) selecionado(s)? Esta ação não pode ser desfeita.`)) return;
    try { await api.deleteFindings(engagement.id, ids); setSel(new Set()); await refresh(); }
    catch (e) { window.alert(`Falha ao excluir: ${e.message}`); }
  }
  function exportFindings() {
    const rows = findings.filter((f) => !sevFilter || f.severity === sevFilter);
    const statusLabel = (f) => (FSTATUS[f.status] || FSTATUS.open).l;
    downloadCsv(`achados_${engagement.client_name || "cliente"}.csv`, rows, [
      { label: "Severidade", key: "severity" },
      { label: "Status", get: statusLabel },
      { label: "Alvo", get: (f) => f.target + (f.port ? `:${f.port}` : "") },
      { label: "Achado", key: "title" },
      { label: "Tipo", get: (f) => TYPE_LABEL[findingType(f)] },
      { label: "CVSS", key: "cvss" },
      { label: "EPSS", key: "epss" },
      { label: "KEV", get: (f) => (f.in_kev ? "SIM" : "") },
      { label: "Confiança", get: (f) => Math.round((f.confidence || 0) * 100) + "%" },
      { label: "Data", get: (f) => (f.created_at ? fmtDateTime(f.created_at) : "") },
      { label: "CVEs", get: (f) => (f.cve_ids || []).join(" ") },
      { label: "Recomendação", get: (f) => (f.ai_assessment || {}).recommendation || "" },
    ]);
  }

  const refresh = useCallback(async () => {
    const [s, f] = await Promise.all([
      api.listScans(engagement.id),
      api.listFindings(engagement.id),
    ]);
    setScans(s);
    setFindings(f);
  }, [engagement.id]);

  async function reenrichCves() {
    setReenriching(true);
    try {
      const r = await api.reenrichCves(engagement.id);
      const d = r.diag || {};
      const prods = Object.entries(d.produtos || {}).map(([k, v]) => `${k}: ${v}`).join("\n  ") || "(nenhum)";
      window.alert(
        `Re-associação concluída (${r.total} achados):\n`
        + `• ${r.confirmed} com CVE CONFIRMADO (produto+versão)\n`
        + `• ${r.potential} com CVE por REGRA (menor severidade; versão não detectada)\n`
        + `   → severidade conservadora atribuída; demais CVEs ficam como possibilidades\n\n`
        + `Achados com produto reconhecido: ${d.com_produto || 0}\n`
        + `Achados sem produto (subdomínios, headers, etc.): ${d.sem_produto || 0}\n\n`
        + `Produtos detectados:\n  ${prods}\n\n`
        + (r.confirmed + r.potential === 0
          ? "Se os produtos acima aparecem mas 0 associou, a base pode não ter CVEs desses produtos — me mande esta mensagem."
          : "Abra os achados para ver os CVEs."));
      await refresh();
    } catch (e) { window.alert(`Falha: ${e.message}`); }
    finally { setReenriching(false); }
  }

  useEffect(() => { refresh(); }, [refresh]);

  // Poll enquanto houver scan rodando.
  useEffect(() => {
    const running = scans.some((s) => s.status === "queued" || s.status === "running");
    if (!running) return;
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [scans, refresh]);

  const [tab, setTab] = useState("dashboard");

  // Sempre que entrar na aba Achados, recarrega (garante que o scan recem
  // iniciado apareca).
  useEffect(() => { if (tab === "ops") refresh(); }, [tab, refresh]);

  return (
    <div>
      <div className="tabs">
        <button className={`tab ${tab === "dashboard" ? "active" : ""}`}
          onClick={() => setTab("dashboard")}>Dashboard</button>
        <button className={`tab ${tab === "tools" ? "active" : ""}`}
          onClick={() => setTab("tools")}>Nova varredura</button>
        <button className={`tab ${tab === "assets" ? "active" : ""}`}
          onClick={() => setTab("assets")}>Ativos</button>
        <button className={`tab ${tab === "ops" ? "active" : ""}`}
          onClick={() => setTab("ops")}>Achados</button>
        <button className={`tab ${tab === "topo" ? "active" : ""}`}
          onClick={() => setTab("topo")}>Topologia</button>
        <button className={`tab ${tab === "docs" ? "active" : ""}`}
          onClick={() => setTab("docs")}>Documentos</button>
      </div>

      {tab === "dashboard" && <Dashboard engagement={engagement} />}
      {tab === "tools" && <ToolCatalog engagement={engagement}
        onUpdated={onUpdated} onRan={() => { setTab("ops"); refresh(); }} />}
      {tab === "assets" && <Assets engagement={engagement} onUpdated={onUpdated} />}
      {tab === "topo" && <Topology engagement={engagement} />}
      {tab === "docs" && <Documents engagement={engagement} />}
      {tab === "ops" && (
      <>
      <div className="head">
        <div>
          <h2>{engagement.name}
            <span className="pill" style={{ background: "#1c476b", marginLeft: 8, fontSize: 11, verticalAlign: "middle" }}>
              {ENG_TYPE_LABEL[engagement.engagement_type] || "Análise de Vulnerabilidades"}
            </span>
            {engagement.allow_exploitation && (
              <span className="pill" style={{ background: "#7f1d1d", marginLeft: 6, fontSize: 11, verticalAlign: "middle" }}>exploração habilitada</span>
            )}
            {engagement.auto_recon && (
              <span className="pill" style={{ background: "#1c476b", marginLeft: 6, fontSize: 11, verticalAlign: "middle" }}>recon auto</span>
            )}
          </h2>
          <p className="muted">{engagement.client_name} · {engagement.scope.join(", ") || "sem escopo"}</p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => setEditingScope(!editingScope)}>Editar escopo</button>
        </div>
      </div>

      {editingScope && (
        <ScopeEditor engagement={engagement}
          onSaved={(upd) => { setEditingScope(false); onUpdated(upd); }}
          onCancel={() => setEditingScope(false)} />
      )}

      {(() => {
        const ACTIVE = ["queued", "running", "paused"];
        const active = scans.filter((s) => ACTIVE.includes(s.status));
        const history = scans.filter((s) => !ACTIVE.includes(s.status));
        const Row = (s) => {
          const running = s.status === "queued" || s.status === "running";
          const paused = s.status === "paused";
          const consoleOpen = consoles.has(s.id);
          return (
            <React.Fragment key={s.id}>
            <tr>
              <td>
                <span className={`status ${s.status}`}>{STATUS_PT[s.status] || s.status}</span>
                <div><button className="btn" title="Ver execução ao vivo (terminal)"
                  style={{ padding: "1px 8px", marginTop: 5, fontSize: 12 }}
                  onClick={() => toggleConsole(s.id)}>{consoleOpen ? "− log" : "+ log"}</button></div>
              </td>
              <td className="muted" style={{ fontSize: 12 }}>
                {scanTypeLabel(s.collectors)}
                {s.auto_level > 0 && <span className="persist" style={{ background: "#1c476b", color: "#dbeafe", borderColor: "#1c476b" }}>auto</span>}
                <div style={{ fontSize: 10, opacity: 0.8 }}>{s.profile === "basic" ? "básico" : "completo"}</div>
              </td>
              <td>
                {running || paused ? (() => {
                  const stale = running && secsSince(s.heartbeat) != null && secsSince(s.heartbeat) > 90;
                  return (
                  <div>
                    <div className="progwrap">
                      <div className="bartrack" style={{ flex: 1 }}><div className="barfill"
                        style={{ width: `${s.progress || 0}%`, background: paused ? "#a16207" : "var(--accent)" }} /></div>
                      <span className="muted" style={{ fontSize: 11, whiteSpace: "nowrap" }}>
                        {s.progress || 0}% · {s.phase || (paused ? "pausado" : "na fila")}</span>
                    </div>
                    {running && s.heartbeat && (
                      <div style={{ fontSize: 10, marginTop: 2, color: stale ? "#f59e0b" : "var(--muted)" }}>
                        {stale ? "⚠ sem atualização " : "● ativo · atualizado "}{agoText(s.heartbeat)}
                        {stale && " (pode estar lento — ainda rodando)"}
                      </div>
                    )}
                  </div>
                  );
                })() : s.status === "failed" ? (
                    <div>
                      <span style={{ color: "#f87171", fontWeight: 600 }}>falhou</span>
                      {s.error && <div style={{ fontSize: 11, color: "#f87171", marginTop: 2, wordBreak: "break-word" }}>⚠ {s.error}</div>}
                    </div>
                  ) : s.status === "cancelled" ? <span className="muted">cancelado</span>
                  : (
                    <div>
                      <span className="muted">concluído</span>
                      {s.error && <div style={{ fontSize: 11, color: "#f59e0b", marginTop: 2, wordBreak: "break-word" }}>⚠ {s.error}</div>}
                    </div>
                  )}
                {Array.isArray(s.stages) && s.stages.length > 0 && (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 5 }}>
                    {s.stages.map((st, i) => {
                      const ic = st.status === "ok" ? "✓" : st.status === "failed" ? "✕"
                        : st.status === "running" ? "⟳" : st.status === "skipped" ? "○" : "·";
                      const col = st.status === "ok" ? "#15803d" : st.status === "failed" ? "#b91c1c"
                        : st.status === "running" ? "var(--accent)" : "#64748b";
                      const tip = st.error || (st.status === "ok"
                        ? `${st.found || 0} coletado(s)${st.created ? `, ${st.created} novo(s)` : ""}`
                        : st.status);
                      return (
                        <span key={i} title={tip} style={{ fontSize: 10, padding: "1px 6px",
                          borderRadius: 10, border: `1px solid ${col}`, color: col, whiteSpace: "nowrap" }}>
                          {ic} {st.label}{st.status === "ok" && st.created ? ` (${st.created})` : ""}
                        </span>
                      );
                    })}
                  </div>
                )}
              </td>
              <td>{s.targets.join(", ")}</td>
              <td className="muted" style={{ fontSize: 11, whiteSpace: "nowrap" }}>
                {fmtDateTime(s.created_at)}
              </td>
              <td>{s.summary || `${s.findings_count || 0} achados`}</td>
              <td style={{ textAlign: "right" }}>
                <div className="row" style={{ gap: 4, justifyContent: "flex-end", flexWrap: "nowrap" }}>
                  {running && <button className="btn" style={{ padding: "3px 10px" }}
                    disabled={busyScan.has(s.id)}
                    title="Pausa e preserva os achados; dá para retomar depois"
                    onClick={() => pauseScan(s.id)}>⏸ Pausar</button>}
                  {paused && <button className="btn primary" style={{ padding: "3px 10px" }}
                    disabled={busyScan.has(s.id)}
                    title="Continua as fases pendentes (sem duplicar achados)"
                    onClick={() => resumeScan(s.id)}>▶ Retomar</button>}
                  {!running && !paused && <button className="btn" style={{ padding: "3px 10px" }}
                    disabled={busyScan.has(s.id)} title="Excluir scan do histórico (mantém achados)"
                    onClick={() => deleteScan(s.id)}>🗑</button>}
                  {(running || paused) && <button className="btn danger" style={{ padding: "3px 10px" }}
                    disabled={busyScan.has(s.id)}
                    onClick={() => cancelScan(s.id)}>{busyScan.has(s.id) ? "Cancelando…" : "⏹ Cancelar"}</button>}
                </div>
              </td>
            </tr>
            {consoleOpen && (
              <tr><td colSpan={7} style={{ padding: 0 }}>
                <ScanConsole scanId={s.id} />
              </td></tr>
            )}
            </React.Fragment>
          );
        };
        return (
        <>
          <h3>Scans em andamento</h3>
          <table className="t">
            <thead><tr><th>Status</th><th>Tipo</th><th style={{ width: "24%" }}>Progresso</th><th>Alvos</th><th>Data/hora</th><th>Resumo</th><th></th></tr></thead>
            <tbody>
              {active.map(Row)}
              {active.length === 0 && <tr><td colSpan={7} className="muted">Nenhum scan em andamento.</td></tr>}
            </tbody>
          </table>

          {history.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <button className="btn" onClick={() => setShowHistory(!showHistory)}>
                {showHistory ? "▾" : "▸"} Histórico de scans ({history.length})
              </button>
              {showHistory && (
                <table className="t">
                  <thead><tr><th>Status</th><th>Tipo</th><th style={{ width: "24%" }}>Progresso</th><th>Alvos</th><th>Data/hora</th><th>Resumo</th><th></th></tr></thead>
                  <tbody>{history.map(Row)}</tbody>
                </table>
              )}
            </div>
          )}
        </>
        );
      })()}

      <div className="row" style={{ justifyContent: "space-between", alignItems: "center", marginTop: 8, flexWrap: "wrap" }}>
        <h3 style={{ margin: 0 }}>Achados ({findings.length})</h3>
        <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
          {["", "critical", "high", "medium", "low", "info"].map((s) => (
            <button key={s || "all"}
              className={`chip ${sevFilter === s ? "active" : ""}`}
              onClick={() => setSevFilter(s)}>{s ? s.toUpperCase() : "TODOS"}</button>
          ))}
          <button className={`chip ${groupByType ? "active" : ""}`}
            title="Agrupar os achados por tipo (e-mails, tecnologias, portas…)"
            onClick={() => setGroupByType((v) => !v)}>⊞ Por tipo</button>
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}
            style={{ width: "auto", padding: "4px 8px", fontSize: 13 }} title="Ordenar por">
            <option value="sev">Ordenar: criticidade</option>
            <option value="date">Ordenar: data (recente)</option>
            <option value="cvss">Ordenar: CVSS</option>
            <option value="target">Ordenar: alvo (A-Z)</option>
          </select>
          <button className="btn" style={{ padding: "4px 10px" }} disabled={reenriching}
            title="Associa CVEs da base local aos achados existentes (produto/versão já detectados), sem re-escanear"
            onClick={reenrichCves}>{reenriching ? "Associando…" : "⟳ Re-associar CVEs"}</button>
          <button className="btn" style={{ padding: "4px 10px" }} title="Exportar achados (CSV)"
            onClick={() => exportFindings()}>⬇ CSV</button>
        </div>
      </div>

      {sel.size > 0 && (
        <div className="selbar">
          <span>{sel.size} selecionado(s)</span>
          <div className="row">
            <button className="btn" onClick={() => setSel(new Set())}>Limpar</button>
            <button className="btn danger" onClick={deleteSelectedFindings}>Excluir selecionados</button>
            <button className="btn primary" onClick={() => { setPickedTool(null); setPickOpen(true); }}>
              Escanear selecionados
            </button>
          </div>
        </div>
      )}

      {(() => {
        const rank = (s) => { const i = SEV_ORDER.indexOf(s); return i < 0 ? 99 : i; };
        const filtered = findings.filter((f) => !sevFilter || f.severity === sevFilter);
        const sorted = [...filtered].sort((a, b) => {
          if (sortBy === "date") return new Date(b.created_at) - new Date(a.created_at);
          if (sortBy === "cvss") return (b.cvss || 0) - (a.cvss || 0);
          if (sortBy === "target") return (a.target || "").localeCompare(b.target || "");
          return rank(a.severity) - rank(b.severity) || (b.cvss || 0) - (a.cvss || 0);
        });

        const renderTable = (rows, headChk) => (
          <table className="t">
            <thead><tr>
              <th>{headChk}</th>
              <th>Sev</th><th>Status</th><th>Alvo</th><th>Achado</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Conf.</th><th>Data</th>
            </tr></thead>
            <tbody>
              {rows.map((f) => <FindingRow key={f.id} f={f}
                selected={sel.has(f.id)} onToggle={toggleSel} onUpdated={refresh} />)}
            </tbody>
          </table>
        );

        if (findings.length === 0) {
          return <div className="muted" style={{ padding: 12 }}>
            Sem achados ainda. Vá em <b>Nova varredura</b> e rode uma ferramenta.</div>;
        }
        if (filtered.length === 0) {
          return <div className="muted" style={{ padding: 12 }}>
            Nenhum achado nesta severidade.</div>;
        }

        if (!groupByType) {
          const allSel = sorted.every((f) => sel.has(f.id));
          const toggleAll = () => setSel(allSel ? new Set() : new Set(sorted.map((f) => f.id)));
          return renderTable(sorted,
            <input type="checkbox" checked={allSel} onChange={toggleAll} />);
        }

        // Agrupado por tipo funcional.
        const groups = {};
        for (const f of sorted) { const t = findingType(f); (groups[t] ||= []).push(f); }
        return (
          <div>
            {TYPE_ORDER.filter((t) => groups[t] && groups[t].length).map((t) => {
              const rows = groups[t];
              const open = !collapsedTypes.has(t);
              const gAll = rows.every((f) => sel.has(f.id));
              const toggleG = () => setSel((prev) => {
                const n = new Set(prev);
                rows.forEach((f) => (gAll ? n.delete(f.id) : n.add(f.id)));
                return n;
              });
              return (
                <div key={t} style={{ marginBottom: 14 }}>
                  <div className="row" style={{ alignItems: "center", gap: 8, cursor: "pointer",
                    padding: "6px 2px", borderBottom: "1px solid var(--border)" }}
                    onClick={() => setCollapsedTypes((prev) => {
                      const n = new Set(prev); n.has(t) ? n.delete(t) : n.add(t); return n; })}>
                    <span style={{ width: 12, color: "var(--muted)" }}>{open ? "▾" : "▸"}</span>
                    <span style={{ fontSize: 15 }}>{TYPE_ICON[t]}</span>
                    <b style={{ fontSize: 14 }}>{TYPE_LABEL[t]}</b>
                    <span className="muted" style={{ fontSize: 12 }}>({rows.length})</span>
                  </div>
                  {open && renderTable(rows,
                    <input type="checkbox" checked={gAll} onChange={toggleG}
                      onClick={(e) => e.stopPropagation()} title="Selecionar todos deste tipo" />)}
                </div>
              );
            })}
          </div>
        );
      })()}

      {/* Escanear os alvos dos achados selecionados */}
      {pickOpen && !pickedTool && (
        <div className="modalOverlay" onClick={() => setPickOpen(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modalHead">
              <h2 style={{ margin: 0 }}>Escanear selecionados</h2>
              <button className="btn" onClick={() => setPickOpen(false)}>✕</button>
            </div>
            <p className="muted">Escolha a ferramenta:</p>
            <div className="toolGrid">
              {FLAT_TOOLS.filter((t) => !(t.needsIntrusive && !engagement.allow_intrusive)).map((t) => (
                <button key={t.name} className="toolCard" onClick={() => setPickedTool(t)}>
                  <div className="toolIcon">{t.icon}</div>
                  <div style={{ flex: 1 }}>
                    <div className="toolName">{t.name}</div>
                    <div className="muted" style={{ fontSize: 12 }}>{t.desc}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
      {pickOpen && pickedTool && (
        <ToolForm engagement={engagement} tool={pickedTool}
          initialTarget={[...new Set(findings.filter((f) => sel.has(f.id))
            .map((f) => (f.target || "").split(":")[0]).filter(Boolean))].join(" ")}
          onClose={() => { setPickOpen(false); setPickedTool(null); }}
          onUpdated={onUpdated}
          onRan={() => { setPickOpen(false); setPickedTool(null); setSel(new Set()); refresh(); }} />
      )}

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
  const [, setBrandV] = useState(0);
  const [helpOpen, setHelpOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [dragClient, setDragClient] = useState(null);
  const [orderTick, setOrderTick] = useState(0);

  // Re-renderiza quando a marca (logo/nome/cores) muda.
  useEffect(() => onBrandingChange(() => setBrandV((v) => v + 1)), []);

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

  const initials = ((user.name || user.email || "?").trim()[0] || "?").toUpperCase();

  function orderedEngagements() {
    let order = [];
    try { order = JSON.parse(localStorage.getItem("client_order_v1") || "[]"); } catch { order = []; }
    const pos = Object.fromEntries(order.map((id, i) => [id, i]));
    return [...engagements].sort((a, b) => (pos[a.id] ?? 1e9) - (pos[b.id] ?? 1e9));
  }
  function reorderClient(fromId, toId) {
    if (!fromId || fromId === toId) return;
    const ids = orderedEngagements().map((e) => e.id);
    ids.splice(ids.indexOf(fromId), 1);
    ids.splice(ids.indexOf(toId), 0, fromId);
    try { localStorage.setItem("client_order_v1", JSON.stringify(ids)); } catch { /* */ }
    setOrderTick((t) => t + 1);
  }

  const clientRow = (e) => (
    <div key={e.id} className={`engrow ${selected?.id === e.id && view === "client" ? "active" : ""} ${dragClient === e.id ? "dragging" : ""}`}
      draggable
      onDragStart={() => setDragClient(e.id)}
      onDragEnd={() => setDragClient(null)}
      onDragOver={(ev) => ev.preventDefault()}
      onDrop={(ev) => { ev.preventDefault(); reorderClient(dragClient, e.id); setDragClient(null); }}
      title="Arraste para reordenar">
      <button className="eng" onClick={() => { setSelected(e); setView("client"); }}>
        <div className="ename">{e.name}</div>
        <div className="eclient muted">{e.client_name}{e.authorized ? "" : " · não autorizado"}</div>
      </button>
      <button className="engdel" title="Excluir cliente"
        onClick={async () => {
          if (!window.confirm(`Excluir o cliente "${e.client_name}" e TODOS os seus scans, achados e evidências?\n\nEsta ação não pode ser desfeita.`)) return;
          try {
            await api.deleteEngagement(e.id);
            if (selected?.id === e.id) { setSelected(null); setView("overview"); }
            load();
          } catch (err) { setError(err.message); }
        }}>🗑</button>
    </div>
  );

  // Admin: agrupa os clientes por consultor (nome do dono). Consultor: lista plana.
  function renderClients() {
    if (engagements.length === 0) return <p className="muted">Nenhum cliente.</p>;
    const list = orderedEngagements();
    if (user.role !== "admin") return list.map(clientRow);
    const groups = {};
    for (const e of list) {
      const k = e.owner_name || "Sem consultor";
      (groups[k] = groups[k] || []).push(e);
    }
    return Object.keys(groups).sort((a, b) => a.localeCompare(b)).map((consultor) => (
      <div key={consultor} className="cgroup">
        <div className="cgrouphead">👤 {consultor} <span className="muted">({groups[consultor].length})</span></div>
        {groups[consultor].map(clientRow)}
      </div>
    ));
  }

  return (
    <div className="shell">
      <header className="topbar">
        <div className="topbrand">
          <button className="brandlink brandname" title="Ir para a tela inicial"
            onClick={() => { setView("overview"); setSelected(null); setMenuOpen(false); }}>
            {branding.appName}
          </button>
        </div>
        <div className="topright">
          <button className="brandlink logolink" title="Ir para a tela inicial"
            onClick={() => { setView("overview"); setSelected(null); setMenuOpen(false); }}>
            <img src={branding.logo} alt={branding.appName} className="brandLogo" />
          </button>
          {user.role === "admin" && (
            <button className={`topbtn ${view === "admin" ? "active" : ""}`} title="Administração"
              onClick={() => { setView("admin"); setSelected(null); setMenuOpen(false); }}>⚙</button>
          )}
          <button className="topbtn" title="Ajuda" onClick={() => setHelpOpen(true)}>?</button>
          <div className="avatarwrap">
            <button className="avatar" title={user.email} onClick={() => setMenuOpen((o) => !o)}>{initials}</button>
            {menuOpen && (
              <>
                <div className="menuback" onClick={() => setMenuOpen(false)} />
                <div className="usermenu">
                  <div className="uname">{user.name || user.email}</div>
                  <div className="muted" style={{ fontSize: 11, marginBottom: 8 }}>{user.email} · {user.role}</div>
                  <button className="btn block" style={{ marginBottom: 6 }}
                    onClick={() => { setProfileOpen(true); setMenuOpen(false); }}>Meu perfil</button>
                  <button className="btn block" onClick={logout}>Sair</button>
                </div>
              </>
            )}
          </div>
        </div>
      </header>
      <div className="app">
      <aside className="sidebar">
        <nav className="nav">
          <button className={`navbtn ${view === "overview" ? "active" : ""}`}
            onClick={() => { setView("overview"); setSelected(null); }}>Visão geral</button>
          <button className={`navbtn ${view === "reports" ? "active" : ""}`}
            onClick={() => { setView("reports"); setSelected(null); }}>Relatório</button>
        </nav>
        <div className="clientshead">{user.role === "admin" ? "Clientes por consultor" : "Meus clientes"}</div>
        <div className="list">
          {renderClients()}
        </div>
        <NewEngagement onCreated={(e) => { load(); setSelected(e); setView("client"); }} />
        {error && <div className="err">{error}</div>}
        <div className="api muted">API: {api.base}</div>
      </aside>
      <main className="main">
        {view === "overview" && <Overview />}
        {view === "reports" && <Reports me={user} />}
        {view === "admin" && <Admin me={user} />}
        {view === "client" && selected && (
          <EngagementView key={selected.id} engagement={selected}
            onDeleted={() => { setSelected(null); setView("overview"); load(); }}
            onUpdated={(e) => { setSelected(e); load(); }} />
        )}
        {view === "client" && !selected && <div className="empty">Selecione um cliente.</div>}
      </main>
      </div>

      {helpOpen && (
        <div className="modalOverlay" onClick={() => setHelpOpen(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modalHead">
              <h2 style={{ margin: 0 }}>Ajuda</h2>
              <button className="btn" onClick={() => setHelpOpen(false)}>✕</button>
            </div>
            <p className="muted">{branding.appName} — plataforma de análise de vulnerabilidades.</p>
            <ul style={{ fontSize: 13, lineHeight: 1.7, paddingLeft: 18 }}>
              <li><b>Visão geral</b>: consolidação de risco e benchmarking de todos os clientes.</li>
              <li><b>Clientes</b> (lista à esquerda): Dashboard, Nova varredura, Ativos e Achados.</li>
              <li><b>⚙ Administração</b> (admin): usuários, base de CVEs, identidade visual e fuso horário.</li>
              <li>Varreduras rodam em background — acompanhe o progresso e o batimento em <b>Achados</b>.</li>
            </ul>
            <div className="modalFoot">
              <button className="btn primary" onClick={() => setHelpOpen(false)}>Entendi</button>
            </div>
          </div>
        </div>
      )}

      {profileOpen && (
        <Profile user={user} onClose={() => setProfileOpen(false)}
          onSaved={(u) => setUser(u)} />
      )}
    </div>
  );
}
