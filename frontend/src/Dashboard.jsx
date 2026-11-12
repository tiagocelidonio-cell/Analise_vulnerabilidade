import React, { useEffect, useState, useCallback } from "react";
import { api } from "./api.js";

// Cor da celula/nivel conforme o score (prob x impacto), 1..25.
function scoreColor(score) {
  if (score >= 20) return "#7f1d1d"; // critico
  if (score >= 15) return "#b91c1c"; // alto
  if (score >= 10) return "#c2410c"; // elevado
  if (score >= 5) return "#a16207";  // moderado
  return "#15803d";                  // baixo
}
const LEVELS = [
  { key: "critico", label: "Crítico", color: "#7f1d1d" },
  { key: "alto", label: "Alto", color: "#b91c1c" },
  { key: "elevado", label: "Elevado", color: "#c2410c" },
  { key: "moderado", label: "Moderado", color: "#a16207" },
  { key: "baixo", label: "Baixo", color: "#15803d" },
];

function RiskMatrix({ matrix }) {
  // matrix[prob-1][impact-1] = contagem. Probabilidade cresce para cima.
  const probs = [5, 4, 3, 2, 1];
  const impacts = [1, 2, 3, 4, 5];
  return (
    <div className="matrixWrap">
      <div className="axisY">Probabilidade →</div>
      <table className="matrix">
        <tbody>
          {probs.map((p) => (
            <tr key={p}>
              <th className="axisN">{p}</th>
              {impacts.map((i) => {
                const n = matrix[p - 1][i - 1];
                const score = p * i;
                return (
                  <td key={i} style={{ background: n ? scoreColor(score) : "#0d1526" }}
                      title={`Prob ${p} x Impacto ${i} = ${score}`}>
                    {n > 0 ? n : ""}
                  </td>
                );
              })}
            </tr>
          ))}
          <tr>
            <th></th>
            {impacts.map((i) => <th key={i} className="axisN">{i}</th>)}
          </tr>
        </tbody>
      </table>
      <div className="axisX">Impacto →</div>
    </div>
  );
}

const SEV_OPTS = [
  { v: "info", l: "Tudo (inclui informativos)" },
  { v: "low", l: "Baixo ou acima" },
  { v: "medium", l: "Médio ou acima" },
  { v: "high", l: "Alto ou acima" },
  { v: "critical", l: "Só crítico" },
];

function ReportConfig({ engagement, onClose }) {
  const [opt, setOpt] = useState({
    min_sev: "info", methodology: true, matrix: true, targets: true, evidence: true,
  });
  const set = (k, v) => setOpt((o) => ({ ...o, [k]: v }));
  const chk = (k, label) => (
    <label className="check"><input type="checkbox" checked={opt[k]}
      onChange={(e) => set(k, e.target.checked)} /> {label}</label>
  );
  return (
    <div className="modalOverlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modalHead">
          <h2 style={{ margin: 0 }}>Configurar relatório</h2>
          <button className="btn" onClick={onClose}>✕</button>
        </div>
        <label className="muted" style={{ fontSize: 12 }}>Severidade mínima a incluir</label>
        <select value={opt.min_sev} onChange={(e) => set("min_sev", e.target.value)}>
          {SEV_OPTS.map((s) => <option key={s.v} value={s.v}>{s.l}</option>)}
        </select>
        <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 6 }}>
          {chk("methodology", "Incluir introdução / metodologia / aviso legal")}
          {chk("matrix", "Incluir matriz de risco")}
          {chk("targets", "Incluir seção de alvos identificados")}
          {chk("evidence", "Incluir evidências (saída bruta)")}
        </div>
        <div className="modalFoot">
          <a className="btn" href={api.reportHtmlUrl(engagement.id, opt)} target="_blank" rel="noreferrer">Preview</a>
          <a className="btn primary" href={api.reportPdfUrl(engagement.id, opt)}>Baixar PDF</a>
        </div>
      </div>
    </div>
  );
}

export default function Dashboard({ engagement }) {
  const [data, setData] = useState(null);
  const [msg, setMsg] = useState("");
  const [cfgOpen, setCfgOpen] = useState(false);

  const load = useCallback(async () => {
    try { setData(await api.risk(engagement.id)); }
    catch (e) { setMsg(e.message); }
  }, [engagement.id]);

  useEffect(() => { load(); }, [load]);

  if (!data) return <div className="muted">Carregando risco…</div>;

  const critAlto = (data.by_level.critico || 0) + (data.by_level.alto || 0);

  return (
    <div>
      <div className="head">
        <div>
          <h2>Painel de risco — {data.engagement.client_name}</h2>
          <p className="muted">{data.engagement.name}</p>
        </div>
        <div className="row">
          <button className="btn" onClick={load}>Atualizar</button>
          <button className="btn primary" onClick={() => setCfgOpen(true)}>📄 Gerar relatório</button>
        </div>
      </div>
      {msg && <div className="err">{msg}</div>}
      {cfgOpen && <ReportConfig engagement={engagement} onClose={() => setCfgOpen(false)} />}

      {/* KPIs executivos */}
      <div className="kpis">
        <div className="kpi"><div className="n">{data.total}</div><div className="l">ACHADOS</div></div>
        <div className="kpi"><div className="n" style={{ color: "#b91c1c" }}>{critAlto}</div><div className="l">CRÍTICO + ALTO</div></div>
        <div className="kpi"><div className="n" style={{ color: "#7f1d1d" }}>{data.kev_count}</div><div className="l">EXPLORADOS (KEV)</div></div>
        <div className="kpi"><div className="n" style={{ color: scoreColor(data.avg_score) }}>{data.avg_score}</div><div className="l">SCORE MÉDIO</div></div>
      </div>

      <div className="dashGrid">
        {/* Matriz de risco */}
        <div className="card">
          <h3>Matriz de risco (probabilidade × impacto)</h3>
          <RiskMatrix matrix={data.matrix} />
          <div className="legend">
            {LEVELS.map((l) => (
              <span key={l.key} className="lg">
                <i style={{ background: l.color }} /> {l.label}
              </span>
            ))}
          </div>
        </div>

        {/* Distribuicao por nivel */}
        <div className="card">
          <h3>Distribuição por nível</h3>
          {LEVELS.map((l) => {
            const n = data.by_level[l.key] || 0;
            const pct = data.total ? Math.round((n / data.total) * 100) : 0;
            return (
              <div key={l.key} className="bar">
                <span className="barlabel">{l.label}</span>
                <div className="bartrack">
                  <div className="barfill" style={{ width: `${pct}%`, background: l.color }} />
                </div>
                <span className="barn">{n}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Top riscos */}
      <div className="card">
        <h3>Top 10 riscos priorizados</h3>
        <table className="t">
          <thead><tr><th>#</th><th>Risco</th><th>Alvo</th><th>CVEs</th><th>Prob.</th><th>Impacto</th><th>Score</th><th>Nível</th></tr></thead>
          <tbody>
            {data.top_risks.map((r, idx) => (
              <tr key={r.id || idx}>
                <td>{idx + 1}</td>
                <td>{r.title}</td>
                <td>{r.target}</td>
                <td>{r.cve_ids && r.cve_ids.length
                  ? r.cve_ids.slice(0, 3).join(", ") + (r.cve_ids.length > 3 ? ` +${r.cve_ids.length - 3}` : "")
                  : "—"}</td>
                <td>{r.probability}</td>
                <td>{r.impact}</td>
                <td><b>{r.score}</b></td>
                <td><span className="pill" style={{ background: scoreColor(r.score) }}>{r.level.toUpperCase()}</span></td>
              </tr>
            ))}
            {data.top_risks.length === 0 && <tr><td colSpan={8} className="muted">Sem achados ainda.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
