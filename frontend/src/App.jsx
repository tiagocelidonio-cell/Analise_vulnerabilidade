import React, { useEffect, useState, useCallback } from "react";
import { api, getToken } from "./api.js";
import { branding } from "./branding.js";
import Dashboard from "./Dashboard.jsx";
import ToolCatalog from "./ToolCatalog.jsx";
import Assets from "./Assets.jsx";
import ToolForm from "./ToolForm.jsx";
import { FLAT_TOOLS } from "./tools.js";
import { downloadCsv } from "./csv.js";
import Overview from "./Overview.jsx";
import Admin from "./Admin.jsx";
import Login from "./Login.jsx";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const STATUS_PT = {
  queued: "na fila", running: "em andamento", completed: "concluído",
  failed: "falhou", cancelled: "cancelado", paused: "pausado",
};
const COLLECTOR_LABEL = {
  port_scan: "Portas (nmap)", http_probe: "Web recon", web_content: "Conteúdo web",
  web_vuln: "Vuln (nuclei)", subdomain_enum: "Subdomínios", wayback: "Wayback",
  google_dorks: "Dorks", validate: "Validação (SAFE)", validate_intrusive: "Validação avançada",
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

function FindingRow({ f, selected, onToggle }) {
  const [open, setOpen] = useState(false);
  const a = f.ai_assessment || {};
  return (
    <>
      <tr className="click" onClick={() => setOpen(!open)}>
        <td onClick={(e) => e.stopPropagation()}>
          <input type="checkbox" checked={selected} onChange={() => onToggle(f)} />
        </td>
        <td><Pill sev={f.severity} /></td>
        <td>{f.target}{f.port ? `:${f.port}` : ""}</td>
        <td>{f.title}
          {f.times_seen > 1 && <span className="persist" title="encontrado em múltiplos scans">
            persiste ×{f.times_seen}</span>}
        </td>
        <td>{f.cvss?.toFixed(1) ?? "-"}</td>
        <td>{f.epss?.toFixed(2) ?? "-"}</td>
        <td>{f.in_kev ? "SIM" : "-"}</td>
        <td>{Math.round(f.confidence * 100)}%</td>
        <td className="muted" style={{ fontSize: 11, whiteSpace: "nowrap" }}>
          {f.created_at ? new Date(f.created_at).toLocaleDateString("pt-BR") : "-"}</td>
      </tr>
      {open && (
        <tr className="detail">
          <td colSpan={9}>
            <p className="muted">
              Visto {f.times_seen || 1}x
              {f.last_seen && ` · última vez ${new Date(f.last_seen).toLocaleString()}`}
              {f.times_seen > 1 && " — a vulnerabilidade PERSISTE após rescan."}
            </p>
            {f.cve_ids?.length > 0 && <p><b>CVEs:</b> {f.cve_ids.join(", ")}</p>}
            <p><b>Risco:</b> {a.risk_summary || "-"}</p>
            <p><b>Explorabilidade:</b> {a.exploitability || "-"}</p>
            <p><b>Recomendacao:</b> {a.recommendation || "-"}</p>
            {a.remediation && <p><b>Remediação (NVD):</b> {a.remediation}</p>}
            {a.references?.length > 0 && (
              <p><b>Referências / patch:</b><br />
                {a.references.map((r) => (
                  <a key={r} href={r} target="_blank" rel="noreferrer"
                    style={{ color: "var(--accent)", display: "block", wordBreak: "break-all" }}>{r}</a>
                ))}
              </p>
            )}
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
  const [sel, setSel] = useState(() => new Set());
  const [pickedTool, setPickedTool] = useState(null);
  const [pickOpen, setPickOpen] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [sortBy, setSortBy] = useState("sev");

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
    downloadCsv(`achados_${engagement.client_name || "cliente"}.csv`, rows, [
      { label: "Severidade", key: "severity" },
      { label: "Alvo", get: (f) => f.target + (f.port ? `:${f.port}` : "") },
      { label: "Serviço", key: "service" },
      { label: "Achado", key: "title" },
      { label: "CVSS", key: "cvss" },
      { label: "EPSS", key: "epss" },
      { label: "KEV", get: (f) => (f.in_kev ? "SIM" : "") },
      { label: "CVEs", get: (f) => (f.cve_ids || []).join(" ") },
      { label: "Confiança", get: (f) => Math.round((f.confidence || 0) * 100) + "%" },
      { label: "Vezes visto", key: "times_seen" },
      { label: "Recomendação", get: (f) => (f.ai_assessment || {}).recommendation || "" },
      { label: "Data", get: (f) => (f.created_at ? new Date(f.created_at).toLocaleString("pt-BR") : "") },
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
      </div>

      {tab === "dashboard" && <Dashboard engagement={engagement} />}
      {tab === "tools" && <ToolCatalog engagement={engagement}
        onUpdated={onUpdated} onRan={() => { setTab("ops"); refresh(); }} />}
      {tab === "assets" && <Assets engagement={engagement} onUpdated={onUpdated} />}
      {tab === "ops" && (
      <>
      <div className="head">
        <div>
          <h2>{engagement.name}</h2>
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
          return (
            <tr key={s.id}>
              <td><span className={`status ${s.status}`}>{STATUS_PT[s.status] || s.status}</span></td>
              <td className="muted" style={{ fontSize: 12 }}>
                {scanTypeLabel(s.collectors)}
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
                })() : s.status === "failed" ? <span className="muted" title={s.error || ""}>falhou</span>
                  : s.status === "cancelled" ? <span className="muted">cancelado</span>
                  : <span className="muted">concluído</span>}
              </td>
              <td>{s.targets.join(", ")}</td>
              <td className="muted" style={{ fontSize: 11, whiteSpace: "nowrap" }}>
                {s.created_at ? new Date(s.created_at).toLocaleString("pt-BR") : "-"}
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
                    onClick={() => cancelScan(s.id)}>{busyScan.has(s.id) ? "Parando…" : "⏹ Parar"}</button>}
                </div>
              </td>
            </tr>
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
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}
            style={{ width: "auto", padding: "4px 8px", fontSize: 13 }} title="Ordenar por">
            <option value="sev">Ordenar: criticidade</option>
            <option value="date">Ordenar: data (recente)</option>
            <option value="cvss">Ordenar: CVSS</option>
            <option value="target">Ordenar: alvo (A-Z)</option>
          </select>
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
        const allSel = sorted.length > 0 && sorted.every((f) => sel.has(f.id));
        const toggleAll = () => setSel(allSel ? new Set() : new Set(sorted.map((f) => f.id)));
        return (
        <table className="t">
          <thead><tr>
            <th><input type="checkbox" checked={allSel} onChange={toggleAll} /></th>
            <th>Sev</th><th>Alvo</th><th>Achado</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Conf.</th><th>Data</th>
          </tr></thead>
          <tbody>
            {sorted.map((f) => <FindingRow key={f.id} f={f}
              selected={sel.has(f.id)} onToggle={toggleSel} />)}
            {findings.length === 0 && <tr><td colSpan={9} className="muted">
              Sem achados ainda. Vá em <b>Nova varredura</b> e rode uma ferramenta.</td></tr>}
          </tbody>
        </table>
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
            <div key={e.id} className={`engrow ${selected?.id === e.id && view === "client" ? "active" : ""}`}>
              <button className="eng"
                onClick={() => { setSelected(e); setView("client"); }}>
                <div className="ename">{e.name}</div>
                <div className="eclient muted">{e.client_name}{e.authorized ? "" : " · nao autorizado"}</div>
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
