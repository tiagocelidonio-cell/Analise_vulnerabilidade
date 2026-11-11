import React, { useEffect, useState, useCallback } from "react";
import { api } from "./api.js";

const SEV = [
  { key: "critical", label: "Crítico", color: "#7f1d1d" },
  { key: "high", label: "Alto", color: "#b91c1c" },
  { key: "medium", label: "Médio", color: "#c2410c" },
  { key: "low", label: "Baixo", color: "#a16207" },
  { key: "info", label: "Info", color: "#334155" },
];
const SEV_COLOR = Object.fromEntries(SEV.map((s) => [s.key, s.color]));

export default function Overview() {
  const [d, setD] = useState(null);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    try { setD(await api.overview()); } catch (e) { setErr(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  if (err) return <div className="err">{err}</div>;
  if (!d) return <div className="muted">Carregando visão geral…</div>;

  const critHigh = (d.severity_dist.critical || 0) + (d.severity_dist.high || 0);
  const maxBench = Math.max(1, ...d.benchmark.map((b) => b.clients));

  return (
    <div>
      <div className="head">
        <div>
          <h2>Visão geral — todos os clientes</h2>
          <p className="muted">Consolidação de risco e benchmarking da base</p>
        </div>
        <button className="btn" onClick={load}>Atualizar</button>
      </div>

      {d.insights.length > 0 && (
        <div className="card">
          <h3>Insights</h3>
          {d.insights.map((t, i) => <p key={i} style={{ margin: "4px 0" }}>• {t}</p>)}
        </div>
      )}

      <div className="kpis">
        <div className="kpi"><div className="n">{d.total_clients}</div><div className="l">CLIENTES</div></div>
        <div className="kpi"><div className="n">{d.total_findings}</div><div className="l">ACHADOS</div></div>
        <div className="kpi"><div className="n" style={{ color: "#b91c1c" }}>{critHigh}</div><div className="l">CRÍTICO + ALTO</div></div>
        <div className="kpi"><div className="n" style={{ color: "#7f1d1d" }}>
          {d.benchmark.reduce((a, b) => a + (b.category.includes("CVE") ? b.occurrences : 0), 0)}
        </div><div className="l">COM CVE</div></div>
      </div>

      <div className="dashGrid">
        {/* Benchmarking */}
        <div className="card">
          <h3>Vulnerabilidades mais comuns (benchmarking)</h3>
          <table className="t">
            <thead><tr><th>Categoria</th><th>Clientes</th><th>Prevalência</th><th>Ocorr.</th><th>Pior</th></tr></thead>
            <tbody>
              {d.benchmark.slice(0, 12).map((b, i) => (
                <tr key={i}>
                  <td>
                    {b.category}
                    <div className="bartrack" style={{ marginTop: 4 }}>
                      <div className="barfill" style={{
                        width: `${(b.clients / maxBench) * 100}%`,
                        background: SEV_COLOR[b.worst_severity] || "#334155" }} />
                    </div>
                  </td>
                  <td>{b.clients}</td>
                  <td>{b.prevalence}%</td>
                  <td>{b.occurrences}</td>
                  <td><span className="pill" style={{ background: SEV_COLOR[b.worst_severity] }}>
                    {b.worst_severity.toUpperCase()}</span></td>
                </tr>
              ))}
              {d.benchmark.length === 0 && <tr><td colSpan={5} className="muted">Sem dados ainda.</td></tr>}
            </tbody>
          </table>
        </div>

        {/* Severidade + clientes em risco */}
        <div className="card">
          <h3>Severidade na base</h3>
          {SEV.map((s) => {
            const n = d.severity_dist[s.key] || 0;
            const pct = d.total_findings ? Math.round((n / d.total_findings) * 100) : 0;
            return (
              <div key={s.key} className="bar">
                <span className="barlabel">{s.label}</span>
                <div className="bartrack"><div className="barfill" style={{ width: `${pct}%`, background: s.color }} /></div>
                <span className="barn">{n}</span>
              </div>
            );
          })}
          <h3 style={{ marginTop: 18 }}>Clientes com maior risco</h3>
          <table className="t">
            <thead><tr><th>Cliente</th><th>Achados</th><th>Crít/Alto</th><th>Score méd.</th></tr></thead>
            <tbody>
              {d.top_clients.map((c, i) => (
                <tr key={i}><td>{c.client}</td><td>{c.total}</td>
                  <td style={{ color: c.crit_high ? "#b91c1c" : "inherit" }}>{c.crit_high}</td>
                  <td>{c.avg_score}</td></tr>
              ))}
              {d.top_clients.length === 0 && <tr><td colSpan={4} className="muted">Sem dados.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
