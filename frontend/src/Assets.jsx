import React, { useEffect, useState, useCallback } from "react";
import { api } from "./api.js";
import { FLAT_TOOLS } from "./tools.js";
import { downloadCsv } from "./csv.js";
import { fmtDateTime } from "./branding.js";
import ToolForm from "./ToolForm.jsx";

const SEV_COLOR = {
  critical: "#7f1d1d", high: "#b91c1c", medium: "#c2410c",
  low: "#a16207", info: "#334155",
};
const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const TYPE_LABEL = { hostname: "HOSTNAME", ip: "IP", range: "RANGE" };

export default function Assets({ engagement, onUpdated }) {
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");
  const [novo, setNovo] = useState("");
  const [sortBy, setSortBy] = useState("risk");
  const [scanTarget, setScanTarget] = useState(null); // alvo(s) a escanear
  const [pickedTool, setPickedTool] = useState(null);  // ferramenta escolhida
  const [sel, setSel] = useState(() => new Set());     // ativos selecionados

  function toggleSel(target) {
    setSel((prev) => {
      const n = new Set(prev);
      n.has(target) ? n.delete(target) : n.add(target);
      return n;
    });
  }

  const load = useCallback(async () => {
    try { setData(await api.assets(engagement.id)); } catch (e) { setErr(e.message); }
  }, [engagement.id]);
  useEffect(() => { load(); }, [load]);

  async function addAssets(list) {
    const entries = list.map((x) => x.trim().toLowerCase()).filter(Boolean);
    if (!entries.length) return;
    const scope = [...new Set([...(engagement.scope || []), ...entries])];
    try {
      const upd = await api.updateEngagement(engagement.id, { scope });
      onUpdated && onUpdated(upd);
      setNovo("");
      await load();
    } catch (e) { setErr(e.message); }
  }

  async function importTxt(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    await addAssets((await file.text()).split(/[\s,;\n]+/));
    e.target.value = "";
  }

  async function removeAsset(target) {
    if (!window.confirm(`Excluir o ativo "${target}" do escopo?`)) return;
    const scope = (engagement.scope || []).filter((s) => s.toLowerCase() !== target.toLowerCase());
    try {
      const upd = await api.updateEngagement(engagement.id, { scope });
      onUpdated && onUpdated(upd);
      await load();
    } catch (e) { setErr(e.message); }
  }

  if (err) return <div className="err">{err}</div>;
  if (!data) return <div className="muted">Carregando ativos…</div>;

  const sorted = [...data.assets].sort((a, b) => {
    if (sortBy === "findings") return b.findings - a.findings;
    if (sortBy === "target") return (a.target || "").localeCompare(b.target || "");
    if (sortBy === "date") return (a.first_seen || "").localeCompare(b.first_seen || "");
    return (SEV_RANK[b.risk] || 1) - (SEV_RANK[a.risk] || 1) || b.findings - a.findings;
  });

  function exportAssets() {
    downloadCsv(`ativos_${engagement.client_name || "cliente"}.csv`, sorted, [
      { label: "Ativo", key: "target" },
      { label: "Tipo", get: (a) => TYPE_LABEL[a.type] || a.type },
      { label: "Risco", get: (a) => (a.risk || "").toUpperCase() },
      { label: "Achados", key: "findings" },
      { label: "Scans", key: "scans" },
      { label: "Identificado em", get: (a) => (a.first_seen ? fmtDateTime(a.first_seen) : "") },
    ]);
  }

  return (
    <div>
      <div className="head">
        <div>
          <h2>Ativos ({data.total})</h2>
          <p className="muted">Hosts, domínios, IPs e ranges do escopo e descobertos.</p>
        </div>
        <div className="row" style={{ gap: 6 }}>
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}
            style={{ width: "auto", padding: "4px 8px", fontSize: 13 }}>
            <option value="risk">Ordenar: risco</option>
            <option value="findings">Ordenar: nº achados</option>
            <option value="date">Ordenar: data (antigo)</option>
            <option value="target">Ordenar: alvo (A-Z)</option>
          </select>
          <button className="btn" onClick={exportAssets} title="Exportar ativos (CSV)">⬇ CSV</button>
          <button className="btn" onClick={load}>Atualizar</button>
        </div>
      </div>

      <div className="card">
        <label className="muted" style={{ fontSize: 12 }}>Adicionar ativo (host, domínio, IP ou range)</label>
        <div className="row">
          <input value={novo} onChange={(e) => setNovo(e.target.value)}
            placeholder="ex: app.cliente.com.br  10.0.0.0/24"
            onKeyDown={(e) => { if (e.key === "Enter") addAssets(novo.split(/[\s,]+/)); }} />
          <button className="btn primary" onClick={() => addAssets(novo.split(/[\s,]+/))}>Adicionar</button>
          <label className="btn" style={{ cursor: "pointer" }}>
            Importar .txt
            <input type="file" accept=".txt" style={{ display: "none" }} onChange={importTxt} />
          </label>
        </div>
      </div>

      {sel.size > 0 && (
        <div className="selbar">
          <span>{sel.size} ativo(s) selecionado(s)</span>
          <div className="row">
            <button className="btn" onClick={() => setSel(new Set())}>Limpar</button>
            <button className="btn primary" onClick={() => {
              setScanTarget([...sel].join(" ")); setPickedTool(null);
            }}>Escanear selecionados</button>
          </div>
        </div>
      )}

      {(() => {
        const allSel = sorted.length > 0 && sorted.every((a) => sel.has(a.target));
        const toggleAll = () => setSel(allSel ? new Set() : new Set(sorted.map((a) => a.target)));
        return (
      <table className="t">
        <thead><tr>
          <th><input type="checkbox" checked={allSel} onChange={toggleAll} /></th>
          <th>Alvo</th><th>Tipo</th><th>Risco</th><th>Achados</th><th>Scans</th><th>Identificado em</th><th></th></tr></thead>
        <tbody>
          {sorted.map((a) => (
            <tr key={a.target}>
              <td onClick={(e) => e.stopPropagation()}>
                <input type="checkbox" checked={sel.has(a.target)} onChange={() => toggleSel(a.target)} />
              </td>
              <td>{a.target}</td>
              <td><span className="typeTag">{TYPE_LABEL[a.type] || a.type}</span></td>
              <td><span className="pill" style={{ background: SEV_COLOR[a.risk] }}>{a.risk.toUpperCase()}</span></td>
              <td>{a.findings}</td>
              <td>{a.scans}</td>
              <td className="muted" style={{ fontSize: 11, whiteSpace: "nowrap" }}>
                {fmtDateTime(a.first_seen)}</td>
              <td className="row" style={{ gap: 6, justifyContent: "flex-end" }}>
                <button className="btn" onClick={() => { setScanTarget(a.target); setPickedTool(null); }}>Escanear</button>
                <button className="btn danger" onClick={() => removeAsset(a.target)}>Excluir</button>
              </td>
            </tr>
          ))}
          {data.assets.length === 0 && <tr><td colSpan={8} className="muted">
            Nenhum ativo. Adicione acima ou rode uma varredura.</td></tr>}
        </tbody>
      </table>
        );
      })()}

      {/* Seletor de ferramenta ao escanear um ativo */}
      {scanTarget && !pickedTool && (
        <div className="modalOverlay" onClick={() => setScanTarget(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modalHead">
              <h2 style={{ margin: 0 }}>
                Escanear {scanTarget.includes(" ") ? `${scanTarget.split(/\s+/).filter(Boolean).length} ativos` : scanTarget}
              </h2>
              <button className="btn" onClick={() => setScanTarget(null)}>✕</button>
            </div>
            {scanTarget.includes(" ") && (
              <p className="muted" style={{ fontSize: 12 }}>{scanTarget.split(/\s+/).filter(Boolean).join(", ")}</p>
            )}
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

      {scanTarget && pickedTool && (
        <ToolForm engagement={engagement} tool={pickedTool} initialTarget={scanTarget}
          onClose={() => { setScanTarget(null); setPickedTool(null); }}
          onUpdated={onUpdated}
          onRan={() => { setScanTarget(null); setPickedTool(null); setSel(new Set()); load(); }} />
      )}
    </div>
  );
}
