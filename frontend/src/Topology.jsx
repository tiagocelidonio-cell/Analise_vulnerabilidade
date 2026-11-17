import React, { useEffect, useRef, useState, useCallback } from "react";
import cytoscape from "cytoscape";
import { api } from "./api.js";

const RISK_COLOR = {
  critical: "#7f1d1d", high: "#b91c1c", medium: "#c2410c",
  low: "#a16207", info: "#475569",
};
const TYPE_SHAPE = {
  domain: "round-rectangle", subdomain: "ellipse", host: "ellipse",
  ip: "diamond", service: "hexagon",
};

export default function Topology({ engagement }) {
  const box = useRef(null);
  const cyRef = useRef(null);
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");
  const [sel, setSel] = useState(null);

  const load = useCallback(async () => {
    try { setData(await api.topology(engagement.id)); } catch (e) { setErr(e.message); }
  }, [engagement.id]);
  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!data || !box.current) return;
    const elements = [
      ...data.nodes.map((n) => ({
        data: { id: n.id, label: n.label, type: n.type, risk: n.risk,
          findings: n.findings, items: n.items || [], techs: n.techs || [] },
      })),
      ...data.edges.map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target } })),
    ];
    const cy = cytoscape({
      container: box.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": (n) => RISK_COLOR[n.data("risk")] || "#475569",
            "shape": (n) => TYPE_SHAPE[n.data("type")] || "ellipse",
            "label": "data(label)", "color": "#e2e8f0", "font-size": 9,
            "text-valign": "bottom", "text-margin-y": 2,
            "width": (n) => 14 + Math.min(20, (n.data("findings") || 0) * 3),
            "height": (n) => 14 + Math.min(20, (n.data("findings") || 0) * 3),
            "border-width": 1, "border-color": "#0b0b0c",
          },
        },
        { selector: "edge", style: { "width": 1, "line-color": "#334155", "curve-style": "haystack", "opacity": 0.6 } },
        { selector: "node:selected", style: { "border-width": 3, "border-color": "#0fdb2b" } },
      ],
      layout: { name: "concentric", concentric: (n) => ({ domain: 5, subdomain: 3, host: 3, ip: 2, service: 1 }[n.data("type")] || 1), minNodeSpacing: 18, levelWidth: () => 2 },
      wheelSensitivity: 0.25,
    });
    cy.on("tap", "node", (ev) => {
      const d = ev.target.data();
      setSel({ id: d.id, type: d.type, risk: d.risk, findings: d.findings,
        items: d.items || [], techs: d.techs || [] });
    });
    cy.on("tap", (ev) => { if (ev.target === cy) setSel(null); });
    cyRef.current = cy;
    return () => cy.destroy();
  }, [data]);

  if (err) return <div className="err">{err}</div>;

  return (
    <div>
      <div className="head"><div>
        <h2>Topologia do ambiente</h2>
        <p className="muted">Nós coloridos por risco; tamanho = nº de achados. Clique para detalhes.</p>
      </div>
        <div className="row">
          <button className="btn" onClick={() => cyRef.current && cyRef.current.fit()}>Ajustar</button>
          <button className="btn" onClick={load}>Atualizar</button>
        </div>
      </div>

      <div className="row" style={{ gap: 14, fontSize: 12, marginBottom: 6, flexWrap: "wrap" }}>
        {Object.entries(RISK_COLOR).map(([k, c]) => (
          <span key={k}><i style={{ display: "inline-block", width: 10, height: 10, background: c, borderRadius: 2, marginRight: 4 }} />{k}</span>
        ))}
        <span className="muted">· ◆ IP · ⬡ serviço · ▭ domínio · ○ host/subdomínio</span>
      </div>

      <div ref={box} style={{ height: "62vh", background: "#0b0b0c", border: "1px solid var(--line)", borderRadius: 10 }} />
      {!data && <div className="muted" style={{ marginTop: 8 }}>Carregando…</div>}
      {data && data.nodes.length === 0 && <p className="muted" style={{ marginTop: 8 }}>
        Sem dados para o grafo. Rode varreduras (portas, subdomínios, web).</p>}

      {sel && (
        <div className="card" style={{ marginTop: 10 }}>
          <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <b style={{ fontSize: 15 }}>{sel.id}</b>
              <span className="muted" style={{ fontSize: 12 }}> · {sel.type}</span>
              {" "}<span className="pill" style={{ background: RISK_COLOR[sel.risk], fontSize: 10 }}>{(sel.risk || "info").toUpperCase()}</span>
              <span className="muted" style={{ fontSize: 12 }}> · {sel.findings || 0} achado(s)</span>
            </div>
            <button className="btn" style={{ padding: "2px 10px" }} onClick={() => setSel(null)}>✕</button>
          </div>

          {sel.techs?.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <b style={{ fontSize: 12 }}>Tecnologias</b>
              <div className="row" style={{ gap: 4, flexWrap: "wrap", marginTop: 4 }}>
                {sel.techs.map((t, i) => (
                  <span key={i} className="pill" style={{ background: "#1c476b", fontSize: 10 }}>{t}</span>
                ))}
              </div>
            </div>
          )}

          <div style={{ marginTop: 10 }}>
            <b style={{ fontSize: 12 }}>Riscos / achados ({sel.items?.length || 0})</b>
            {(sel.items || []).length === 0 ? (
              <p className="muted" style={{ fontSize: 12, margin: "4px 0" }}>Sem achados neste item.</p>
            ) : (
              <table className="t" style={{ marginTop: 4 }}>
                <thead><tr><th>Sev</th><th>Achado</th><th>CVSS</th><th>CVEs</th></tr></thead>
                <tbody>
                  {[...sel.items].sort((a, b) => {
                    const o = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                    return (o[a.severity] ?? 5) - (o[b.severity] ?? 5);
                  }).map((it, i) => (
                    <tr key={i}>
                      <td><span className="pill" style={{ background: RISK_COLOR[it.severity] || "#475569", fontSize: 10 }}>{(it.severity || "info").toUpperCase()}</span></td>
                      <td style={{ fontSize: 12 }}>{it.title}</td>
                      <td>{it.cvss != null ? it.cvss.toFixed(1) : "—"}</td>
                      <td style={{ fontSize: 11 }}>
                        {(it.cve_ids || []).map((c, j) => (
                          <span key={c}>{j > 0 && ", "}
                            <a href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>{c}</a>
                          </span>
                        )) || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
