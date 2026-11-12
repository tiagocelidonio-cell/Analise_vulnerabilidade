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
  const [cveSt, setCveSt] = useState(null);
  const [cveMsg, setCveMsg] = useState("");

  const load = useCallback(async () => {
    try { setD(await api.overview()); } catch (e) { setErr(e.message); }
  }, []);
  const loadCve = useCallback(async () => {
    try { setCveSt(await api.cveStatus()); } catch { /* ignore */ }
  }, []);
  useEffect(() => { load(); loadCve(); }, [load, loadCve]);

  async function updateCve(full) {
    setCveMsg(full ? "Importando base completa (pode demorar)…" : "Atualizando CVEs vistos…");
    try {
      const r = await api.cveUpdate(full);
      setCveMsg(r.mensagem || "Atualização iniciada.");
      setTimeout(loadCve, 4000);
    } catch (e) { setCveMsg(`Falha: ${e.message}`); }
  }

  if (err) return <div className="err">{err}</div>;
  if (!d) return <div className="muted">Carregando visão geral…</div>;

  const critHigh = (d.severity_dist.critical || 0) + (d.severity_dist.high || 0);
  const maxBench = Math.max(1, ...d.benchmark.map((b) => b.clients));
  const cve = d.cve_stats || { distinct: 0, kev: 0, high_epss: 0, top: [], sources: "" };
  const fmtPct = (x) => (x == null ? "—" : `${Math.round(x * 100)}%`);

  return (
    <div>
      <div className="head">
        <div>
          <h2>Visão geral — todos os clientes</h2>
          <p className="muted">Consolidação de risco e benchmarking da base</p>
        </div>
        <div className="row">
          <button className="btn" onClick={load}>Atualizar</button>
          <a className="btn" href={api.overviewReportHtmlUrl()} target="_blank" rel="noreferrer">Preview</a>
          <a className="btn primary" href={api.overviewReportPdfUrl()}>Relatório PDF</a>
        </div>
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
        <div className="kpi"><div className="n" style={{ color: "#7f1d1d" }}>{cve.distinct}</div><div className="l">CVEs DISTINTOS</div></div>
        <div className="kpi"><div className="n" style={{ color: "#b91c1c" }}>{cve.kev}</div><div className="l">KEV (EXPL. ATIVA)</div></div>
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

      {/* Base de CVEs detectada na carteira (atualizada a cada scan) */}
      <div className="card">
        <div className="row" style={{ justifyContent: "space-between", alignItems: "baseline" }}>
          <h3 style={{ margin: 0 }}>Base de CVEs — mais relevantes na carteira</h3>
          <span className="muted" style={{ fontSize: 11 }}>
            {cve.distinct} CVEs · {cve.kev} em KEV · {cve.high_epss} com EPSS ≥ 50%
          </span>
        </div>
        <p className="muted" style={{ fontSize: 12, margin: "2px 0 8px" }}>
          Fontes: {cve.sources}. Atualizada a cada varredura; prevalência = % de
          clientes afetados (anônimo, para benchmarking).
        </p>
        <div className="row" style={{ gap: 8, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
          <span className="muted" style={{ fontSize: 12 }}>
            Base local: <b>{cveSt?.count ?? "—"}</b> CVEs
            {cveSt?.last_updated && ` · atualizada ${new Date(cveSt.last_updated).toLocaleString("pt-BR")}`}
          </span>
          <button className="btn" style={{ padding: "3px 10px" }} onClick={() => updateCve(false)}>
            ↻ Atualizar vistos
          </button>
          <button className="btn" style={{ padding: "3px 10px" }} onClick={() => updateCve(true)}
            title="Baixa o bundle oficial (CVE List JSON 5.0). Pesado. Só admin.">
            ⬇ Importar base completa
          </button>
          {cveMsg && <span className="muted" style={{ fontSize: 12 }}>{cveMsg}</span>}
        </div>
        <table className="t">
          <thead><tr><th>CVE</th><th>Clientes</th><th>Prevalência</th><th>CVSS</th><th>EPSS</th><th>KEV</th></tr></thead>
          <tbody>
            {cve.top.map((c) => (
              <tr key={c.cve_id}>
                <td>
                  <a href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`}
                    target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>{c.cve_id}</a>
                </td>
                <td>{c.clients}</td>
                <td>{c.prevalence}%</td>
                <td>{c.cvss != null ? c.cvss.toFixed(1) : "—"}</td>
                <td>{fmtPct(c.epss)}</td>
                <td>{c.in_kev ? <span className="pill" style={{ background: "#b91c1c" }}>KEV</span> : "—"}</td>
              </tr>
            ))}
            {cve.top.length === 0 && <tr><td colSpan={6} className="muted">
              Nenhum CVE detectado ainda. Rode um Vulnerability Scanner (nuclei) ou Port Scanner com versão.
            </td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}
