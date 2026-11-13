import React, { useEffect, useState, useCallback } from "react";
import { api } from "./api.js";
import { downloadCsv } from "./csv.js";
import { fmtDateTime } from "./branding.js";

// Tela de Relatórios: relatório consolidado (PDF/preview) + exportações CSV.
export default function Reports() {
  const [d, setD] = useState(null);
  const [engs, setEngs] = useState([]);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    try {
      const [ov, es] = await Promise.all([api.overview(), api.listEngagements()]);
      setD(ov); setEngs(es);
    } catch (e) { setErr(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  if (err) return <div className="err">{err}</div>;
  if (!d) return <div className="muted">Carregando…</div>;

  function exportClients() {
    downloadCsv("clientes_resumo.csv", d.top_clients || [], [
      { label: "Cliente", key: "client" },
      { label: "Achados", key: "total" },
      { label: "Crítico/Alto", key: "crit_high" },
      { label: "Score médio", key: "avg_score" },
    ]);
  }
  function exportBenchmark() {
    downloadCsv("benchmarking.csv", d.benchmark || [], [
      { label: "Categoria", key: "category" },
      { label: "Clientes", key: "clients" },
      { label: "Prevalência (%)", key: "prevalence" },
      { label: "Ocorrências", key: "occurrences" },
      { label: "Pior severidade", key: "worst_severity" },
    ]);
  }
  function exportCves() {
    downloadCsv("base_cves.csv", (d.cve_stats || {}).top || [], [
      { label: "CVE", key: "cve_id" },
      { label: "Clientes", key: "clients" },
      { label: "Prevalência (%)", key: "prevalence" },
      { label: "CVSS", key: "cvss" },
      { label: "EPSS", get: (c) => (c.epss != null ? Math.round(c.epss * 100) + "%" : "") },
      { label: "KEV", get: (c) => (c.in_kev ? "SIM" : "") },
    ]);
  }
  async function exportAllFindings() {
    setBusy("Reunindo achados de todos os clientes…");
    try {
      const rows = [];
      for (const e of engs) {
        let fs = [];
        try { fs = await api.listFindings(e.id); } catch { fs = []; }
        for (const f of fs) {
          rows.push({
            cliente: e.client_name, engajamento: e.name,
            severity: f.severity, target: f.target + (f.port ? `:${f.port}` : ""),
            service: f.service, title: f.title, cvss: f.cvss, epss: f.epss,
            kev: f.in_kev ? "SIM" : "", cves: (f.cve_ids || []).join(" "),
            confianca: Math.round((f.confidence || 0) * 100) + "%",
            recomendacao: (f.ai_assessment || {}).recommendation || "",
            data: f.created_at ? fmtDateTime(f.created_at) : "",
          });
        }
      }
      downloadCsv("achados_todos_clientes.csv", rows, [
        { label: "Cliente", key: "cliente" }, { label: "Engajamento", key: "engajamento" },
        { label: "Severidade", key: "severity" }, { label: "Alvo", key: "target" },
        { label: "Serviço", key: "service" }, { label: "Achado", key: "title" },
        { label: "CVSS", key: "cvss" }, { label: "EPSS", key: "epss" },
        { label: "KEV", key: "kev" }, { label: "CVEs", key: "cves" },
        { label: "Confiança", key: "confianca" }, { label: "Recomendação", key: "recomendacao" },
        { label: "Data", key: "data" },
      ]);
      setBusy("");
    } catch (e) { setErr(e.message); setBusy(""); }
  }

  return (
    <div>
      <p className="muted" style={{ marginTop: 0 }}>
        Dados consolidados de todos os clientes — visível apenas para o administrador.
      </p>

      <div className="card" style={{ maxWidth: 680 }}>
        <h3>Relatório consolidado (todos os clientes)</h3>
        <p className="muted" style={{ fontSize: 13 }}>
          Consolidação anônima de risco e benchmarking — sem expor nomes de clientes.
        </p>
        <div className="row" style={{ gap: 8 }}>
          <a className="btn" href={api.overviewReportHtmlUrl()} target="_blank" rel="noreferrer">👁 Preview</a>
          <a className="btn primary" href={api.overviewReportPdfUrl()}>📄 Relatório PDF</a>
        </div>
      </div>

      <div className="card" style={{ maxWidth: 680 }}>
        <h3>Exportar dados (CSV)</h3>
        <p className="muted" style={{ fontSize: 13 }}>Baixe os dados para planilha (abre no Excel).</p>
        <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
          <button className="btn primary" onClick={exportAllFindings} disabled={!!busy}>
            ⬇ Achados (todos os clientes)
          </button>
          <button className="btn" onClick={exportClients}>⬇ Clientes (resumo)</button>
          <button className="btn" onClick={exportBenchmark}>⬇ Benchmarking</button>
          <button className="btn" onClick={exportCves}>⬇ Base de CVEs</button>
        </div>
        {busy && <div className="info" style={{ marginTop: 8 }}>{busy}</div>}
      </div>
    </div>
  );
}
