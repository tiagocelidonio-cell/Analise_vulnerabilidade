import React, { useEffect, useState, useCallback } from "react";
import { api } from "./api.js";
import { fmtDateTime } from "./branding.js";
import CustomDashboard from "./CustomDashboard.jsx";

const SEV = [
  { key: "critical", label: "Crítico", color: "#7f1d1d" },
  { key: "high", label: "Alto", color: "#b91c1c" },
  { key: "medium", label: "Médio", color: "#c2410c" },
  { key: "low", label: "Baixo", color: "#a16207" },
  { key: "info", label: "Info", color: "#334155" },
];
const SEV_COLOR = Object.fromEntries(SEV.map((s) => [s.key, s.color]));
const fmtPct = (x) => (x == null ? "—" : `${Math.round(x * 100)}%`);

export default function Overview() {
  const [d, setD] = useState(null);
  const [err, setErr] = useState("");
  const [cveSt, setCveSt] = useState(null);
  const [recent, setRecent] = useState([]);
  const [rel, setRel] = useState(null);
  const [relAll, setRelAll] = useState(false);
  const [recentAll, setRecentAll] = useState(false);

  const load = useCallback(async () => {
    try { setD(await api.overview()); } catch (e) { setErr(e.message); }
  }, []);
  const loadCve = useCallback(async () => {
    try { setCveSt(await api.cveStatus()); } catch { /* ignore */ }
    try { setRecent((await api.cveRecent(30)).cves || []); } catch { /* ignore */ }
    try { setRel(await api.intelRelevant()); } catch { /* ignore */ }
  }, []);
  useEffect(() => { load(); loadCve(); }, [load, loadCve]);

  if (err) return <div className="err">{err}</div>;
  if (!d) return <div className="muted">Carregando visão geral…</div>;

  const critHigh = (d.severity_dist.critical || 0) + (d.severity_dist.high || 0);
  const maxBench = Math.max(1, ...d.benchmark.map((b) => b.clients));
  const cve = d.cve_stats || { distinct: 0, kev: 0, high_epss: 0, top: [], sources: "" };

  const kpi = (n, l, color) => (
    <div className="kpi"><div className="n" style={color ? { color } : undefined}>{n}</div><div className="l">{l}</div></div>
  );

  const widgets = [
    {
      id: "kpis", title: "Indicadores", wide: true, node: (
        <div className="kpis" style={{ margin: 0 }}>
          {kpi(d.total_clients, "CLIENTES")}
          {kpi(d.total_findings, "ACHADOS")}
          {kpi(critHigh, "CRÍTICO + ALTO", "#b91c1c")}
          {kpi(cve.distinct, "CVEs DISTINTOS", "#7f1d1d")}
          {kpi(cve.kev, "KEV (EXPL. ATIVA)", "#b91c1c")}
        </div>
      ),
    },
    {
      id: "insights", title: "Insights", wide: true, node: (
        d.insights.length > 0
          ? d.insights.map((t, i) => <p key={i} style={{ margin: "4px 0" }}>• {t}</p>)
          : <p className="muted">Sem insights ainda.</p>
      ),
    },
    {
      id: "relevant", title: "⚡ Relevantes para a sua carteira", wide: true, node: (
        !rel ? <p className="muted">Carregando…</p>
          : rel.matches.length === 0 ? (
            <p className="muted">
              Nenhum CVE recente casou com as tecnologias detectadas
              {rel.counts?.technologies ? ` (${rel.counts.technologies} tecnologias mapeadas)` : ""}.
              {" "}Rode varreduras com <b>Tecnologias</b> e baixe a <b>base completa de CVEs</b>
              {" "}(captura os produtos afetados) para ativar os alertas.
            </p>
          ) : (() => {
            const counts = SEV.reduce((a, s) => {
              a[s.key] = rel.matches.filter((m) => m.severity === s.key).length; return a;
            }, {});
            const shown = relAll ? rel.matches : rel.matches.slice(0, 12);
            return (
            <>
              <div className="info" style={{ fontSize: 12, marginBottom: 8 }}>
                <b>Exposição potencial</b> — {rel.counts.matches} CVE(s) recente(s) afetam
                uma tecnologia detectada em <b>{rel.counts.clients}</b> cliente(s).
                Isto <b>não é um achado confirmado</b>: indica que o produto tem CVE novo;
                confirme a <b>versão</b> do ativo para saber se está vulnerável.
              </div>
              {/* resumo por severidade */}
              <div className="row" style={{ gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
                {SEV.filter((s) => counts[s.key]).map((s) => (
                  <span key={s.key} className="pill" style={{ background: s.color, fontSize: 11 }}>
                    {s.label}: {counts[s.key]}
                  </span>
                ))}
              </div>
              <table className="t">
                <thead><tr>
                  <th>Publicado</th><th>CVE</th><th>Sev</th><th>CVSS</th>
                  <th>Cliente(s)</th><th>Tecnologia</th><th>Match</th>
                </tr></thead>
                <tbody>
                  {shown.map((m) => (
                    <tr key={m.cve_id}>
                      <td className="muted" style={{ fontSize: 12, whiteSpace: "nowrap" }}>{m.published ? fmtDateTime(m.published) : "—"}</td>
                      <td><a href={`https://nvd.nist.gov/vuln/detail/${m.cve_id}`} target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>{m.cve_id}</a></td>
                      <td><span className="pill" style={{ background: SEV_COLOR[m.severity] || "#334155", fontSize: 10 }}>{m.severity.toUpperCase()}</span></td>
                      <td>{m.cvss != null ? m.cvss.toFixed(1) : "—"}</td>
                      <td style={{ fontSize: 12 }}>{m.clients.join(", ") || "—"}</td>
                      <td style={{ fontSize: 12 }}>{m.technologies.join(", ")}</td>
                      <td><span className="pill" style={{ background: m.confidence === "alta" ? "#15803d" : "#a16207", fontSize: 10 }}>{m.confidence === "alta" ? "produto" : "descrição"}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {rel.matches.length > 12 && (
                <button className="btn" style={{ marginTop: 6, padding: "3px 10px" }}
                  onClick={() => setRelAll((v) => !v)}>
                  {relAll ? "▲ Mostrar só os 12 principais" : `▼ Mostrar todos (${rel.matches.length})`}
                </button>
              )}
              <p className="muted" style={{ fontSize: 11, marginTop: 6 }}>
                <b>produto</b> = o produto afetado bate com o CPE do CVE · <b>descrição</b> =
                citado só na descrição. Ordenado por força do match e CVSS.
              </p>
            </>
            );
          })()
      ),
    },
    {
      id: "benchmark", title: "Vulnerabilidades mais comuns (benchmarking)", node: (
        <table className="t">
          <thead><tr><th>Categoria</th><th>Clientes</th><th>Prev.</th><th>Ocorr.</th><th>Pior</th></tr></thead>
          <tbody>
            {d.benchmark.slice(0, 12).map((b, i) => (
              <tr key={i}>
                <td>{b.category}
                  <div className="bartrack" style={{ marginTop: 4 }}>
                    <div className="barfill" style={{ width: `${(b.clients / maxBench) * 100}%`,
                      background: SEV_COLOR[b.worst_severity] || "#334155" }} /></div>
                </td>
                <td>{b.clients}</td><td>{b.prevalence}%</td><td>{b.occurrences}</td>
                <td><span className="pill" style={{ background: SEV_COLOR[b.worst_severity] }}>{b.worst_severity.toUpperCase()}</span></td>
              </tr>
            ))}
            {d.benchmark.length === 0 && <tr><td colSpan={5} className="muted">Sem dados ainda.</td></tr>}
          </tbody>
        </table>
      ),
    },
    {
      id: "severity", title: "Severidade na base", node: (
        SEV.map((s) => {
          const n = d.severity_dist[s.key] || 0;
          const pct = d.total_findings ? Math.round((n / d.total_findings) * 100) : 0;
          return (
            <div key={s.key} className="bar">
              <span className="barlabel">{s.label}</span>
              <div className="bartrack"><div className="barfill" style={{ width: `${pct}%`, background: s.color }} /></div>
              <span className="barn">{n}</span>
            </div>
          );
        })
      ),
    },
    {
      id: "topclients", title: "Clientes com maior risco", node: (
        <table className="t">
          <thead><tr><th>Cliente</th><th>Achados</th><th>Crít/Alto</th><th>Score</th></tr></thead>
          <tbody>
            {d.top_clients.map((c, i) => (
              <tr key={i}><td>{c.client}</td><td>{c.total}</td>
                <td style={{ color: c.crit_high ? "#b91c1c" : "inherit" }}>{c.crit_high}</td>
                <td>{c.avg_score}</td></tr>
            ))}
            {d.top_clients.length === 0 && <tr><td colSpan={4} className="muted">Sem dados.</td></tr>}
          </tbody>
        </table>
      ),
    },
    {
      id: "cverecent", title: "📰 CVEs recentes (feed de notícias)", wide: true, node: (
        recent.length === 0
          ? <p className="muted">Sem CVEs recentes. Baixe a base completa em <b>Administração › Base de CVEs</b> (captura a data de publicação).</p>
          : (() => {
            const shown = recentAll ? recent : recent.slice(0, 8);
            return (
            <>
              <table className="t">
                <thead><tr><th>Publicado</th><th>CVE</th><th>Sev</th><th>CVSS</th><th>Descrição</th></tr></thead>
                <tbody>
                  {shown.map((c) => (
                    <tr key={c.cve_id}>
                      <td className="muted" style={{ fontSize: 12, whiteSpace: "nowrap" }}>{c.published ? fmtDateTime(c.published) : "—"}</td>
                      <td><a href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`} target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>{c.cve_id}</a></td>
                      <td><span className="pill" style={{ background: SEV_COLOR[c.severity] || "#334155", fontSize: 10 }}>{c.severity.toUpperCase()}</span></td>
                      <td>{c.cvss != null ? c.cvss.toFixed(1) : "—"}</td>
                      <td style={{ fontSize: 12 }}>{(c.description || "").slice(0, 140)}{(c.description || "").length > 140 ? "…" : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {recent.length > 8 && (
                <button className="btn" style={{ marginTop: 6, padding: "3px 10px" }}
                  onClick={() => setRecentAll((v) => !v)}>
                  {recentAll ? "▲ Mostrar menos" : `▼ Mostrar todos (${recent.length})`}
                </button>
              )}
            </>
            );
          })()
      ),
    },
    {
      id: "cvebase", title: "Base de CVEs — mais relevantes", wide: true, node: (
        <>
          <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>
            {cve.distinct} CVEs · {cve.kev} em KEV · {cve.high_epss} com EPSS ≥ 50% ·
            base local: <b>{cveSt?.count ?? "—"}</b>
            {cveSt?.last_updated && ` · atualizada ${fmtDateTime(cveSt.last_updated)}`}
          </div>
          <table className="t">
            <thead><tr><th>CVE</th><th>Clientes</th><th>Prev.</th><th>CVSS</th><th>EPSS</th><th>KEV</th></tr></thead>
            <tbody>
              {cve.top.map((c) => (
                <tr key={c.cve_id}>
                  <td><a href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`} target="_blank" rel="noreferrer"
                    style={{ color: "var(--accent)" }}>{c.cve_id}</a></td>
                  <td>{c.clients}</td><td>{c.prevalence}%</td>
                  <td>{c.cvss != null ? c.cvss.toFixed(1) : "—"}</td>
                  <td>{fmtPct(c.epss)}</td>
                  <td>{c.in_kev ? <span className="pill" style={{ background: "#b91c1c" }}>KEV</span> : "—"}</td>
                </tr>
              ))}
              {cve.top.length === 0 && <tr><td colSpan={6} className="muted">Nenhum CVE detectado ainda.</td></tr>}
            </tbody>
          </table>
        </>
      ),
    },
  ];

  const actions = (
    <button className="btn" onClick={() => { load(); loadCve(); }}>Atualizar</button>
  );

  return (
    <CustomDashboard storageKey="dash_overview_v1" widgets={widgets} actions={actions}
      title="Visão geral — todos os clientes"
      subtitle="Consolidação de risco e benchmarking da base" />
  );
}
