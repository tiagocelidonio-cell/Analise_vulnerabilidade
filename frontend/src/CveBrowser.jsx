import React, { useState, useCallback, useEffect } from "react";
import { api } from "./api.js";

const SEV_COLOR = { critical: "#7f1d1d", high: "#b91c1c", medium: "#c2410c", low: "#a16207", info: "#334155" };
const PAGE = 50;

// Consulta a base de CVE baixada: texto, severidade, produto/tecnologia e datas.
export default function CveBrowser() {
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [product, setProduct] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [data, setData] = useState(null);
  const [offset, setOffset] = useState(0);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const search = useCallback(async (off = 0) => {
    setBusy(true); setErr("");
    try {
      const params = { limit: PAGE, offset: off };
      if (q) params.q = q;
      if (severity) params.severity = severity;
      if (product) params.product = product;
      if (dateFrom) params.date_from = dateFrom;
      if (dateTo) params.date_to = dateTo;
      const r = await api.cveSearch(params);
      setData(r); setOffset(off);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }, [q, severity, product, dateFrom, dateTo]);

  useEffect(() => { search(0); /* carga inicial */ }, []); // eslint-disable-line

  const total = data?.total || 0;
  const items = data?.items || [];
  const onSubmit = (e) => { e.preventDefault(); search(0); };

  return (
    <div>
      <p className="muted" style={{ marginTop: 0 }}>
        Consulte todos os CVEs baixados. Filtre por texto, severidade, produto/tecnologia e data de publicação.
      </p>
      <form onSubmit={onSubmit}>
        <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "flex-end" }}>
          <div style={{ flex: "2 1 220px" }}>
            <label className="muted" style={{ fontSize: 11 }}>Texto (CVE-ID ou descrição)</label>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="ex.: CVE-2021-41773, path traversal…" />
          </div>
          <div style={{ flex: "1 1 140px" }}>
            <label className="muted" style={{ fontSize: 11 }}>Produto / tecnologia</label>
            <input value={product} onChange={(e) => setProduct(e.target.value)} placeholder="ex.: apache, openssh, mysql" />
          </div>
          <div>
            <label className="muted" style={{ fontSize: 11, display: "block" }}>Severidade</label>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} style={{ width: "auto" }}>
              <option value="">Todas</option>
              <option value="critical">Crítico</option>
              <option value="high">Alto</option>
              <option value="medium">Médio</option>
              <option value="low">Baixo</option>
            </select>
          </div>
          <div>
            <label className="muted" style={{ fontSize: 11, display: "block" }}>Publicado de</label>
            <input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} style={{ width: "auto" }} />
          </div>
          <div>
            <label className="muted" style={{ fontSize: 11, display: "block" }}>até</label>
            <input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)} style={{ width: "auto" }} />
          </div>
          <button className="btn primary" type="submit" disabled={busy}>{busy ? "Buscando…" : "Buscar"}</button>
        </div>
      </form>

      {err && <div className="err" style={{ marginTop: 8 }}>{err}</div>}

      <div className="muted" style={{ fontSize: 12, margin: "10px 0 4px" }}>
        {total.toLocaleString("pt-BR")} resultado(s){total > 0 && ` · mostrando ${offset + 1}–${Math.min(offset + PAGE, total)}`}
      </div>
      <table className="t">
        <thead><tr><th>Publicado</th><th>CVE</th><th>Sev</th><th>CVSS</th><th>Produtos</th><th>Descrição</th></tr></thead>
        <tbody>
          {items.map((c) => (
            <tr key={c.cve_id}>
              <td className="muted" style={{ fontSize: 12, whiteSpace: "nowrap" }}>{c.published ? c.published.slice(0, 10) : "—"}</td>
              <td><a href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`} target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>{c.cve_id}</a></td>
              <td><span className="pill" style={{ background: SEV_COLOR[c.severity] || "#334155", fontSize: 10 }}>{c.severity.toUpperCase()}</span></td>
              <td>{c.cvss != null ? c.cvss.toFixed(1) : "—"}</td>
              <td style={{ fontSize: 11 }}>{(c.products || []).join(", ") || "—"}</td>
              <td style={{ fontSize: 12 }}>{(c.description || "").slice(0, 160)}{(c.description || "").length > 160 ? "…" : ""}</td>
            </tr>
          ))}
          {items.length === 0 && !busy && <tr><td colSpan={6} className="muted">Nenhum CVE encontrado com esses filtros.</td></tr>}
        </tbody>
      </table>

      {total > PAGE && (
        <div className="row" style={{ gap: 8, marginTop: 8, justifyContent: "center" }}>
          <button className="btn" disabled={offset === 0 || busy} onClick={() => search(Math.max(0, offset - PAGE))}>← Anterior</button>
          <span className="muted" style={{ fontSize: 12, alignSelf: "center" }}>página {Math.floor(offset / PAGE) + 1} de {Math.ceil(total / PAGE)}</span>
          <button className="btn" disabled={offset + PAGE >= total || busy} onClick={() => search(offset + PAGE)}>Próxima →</button>
        </div>
      )}
    </div>
  );
}
