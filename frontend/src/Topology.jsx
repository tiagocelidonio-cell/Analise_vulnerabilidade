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

const RISK_HEX = {
  critical: "7f1d1d", high: "b91c1c", medium: "c2410c", low: "a16207", info: "475569",
};

export default function Topology({ engagement }) {
  const box = useRef(null);
  const boxWrap = useRef(null);
  const cyRef = useRef(null);
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");
  const [sel, setSel] = useState(null);
  const [stats, setStats] = useState({ nodes: 0, edges: 0, orphans: 0 });
  const [busy, setBusy] = useState("");
  const [fs, setFs] = useState(false);

  const load = useCallback(async () => {
    try { setData(await api.topology(engagement.id)); } catch (e) { setErr(e.message); }
  }, [engagement.id]);
  useEffect(() => { load(); }, [load]);

  // Zoom / ajuste.
  function zoomBy(f) {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({ level: cy.zoom() * f,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  }
  // Tela cheia (sobre o container do grafo).
  function toggleFs() {
    const el = boxWrap.current;
    if (!el) return;
    if (!document.fullscreenElement) el.requestFullscreen?.();
    else document.exitFullscreen?.();
  }
  useEffect(() => {
    function onFs() {
      setFs(!!document.fullscreenElement);
      const cy = cyRef.current;
      if (cy) setTimeout(() => { cy.resize(); cy.fit(undefined, 30); }, 120);
    }
    document.addEventListener("fullscreenchange", onFs);
    return () => document.removeEventListener("fullscreenchange", onFs);
  }, []);

  const _slug = (engagement.name || "ambiente").replace(/[^\w.-]+/g, "_").slice(0, 60);

  function exportPng() {
    const cy = cyRef.current;
    if (!cy || cy.nodes().length === 0) { setErr("Nada para exportar — rode varreduras primeiro."); return; }
    const png = cy.png({ full: true, scale: 2, bg: "#0b0b0c" });
    const a = document.createElement("a");
    a.href = png; a.download = `topologia-${_slug}.png`;
    document.body.appendChild(a); a.click(); a.remove();
  }

  // PPT com ELEMENTOS NATIVOS editáveis (formas + conectores + rótulos), não
  // uma imagem estática — o usuário pode mover/editar cada nó no PowerPoint.
  async function exportPpt() {
    const cy = cyRef.current;
    if (!cy || cy.nodes().length === 0) { setErr("Nada para exportar — rode varreduras primeiro."); return; }
    setBusy("ppt");
    try {
      const PptxGenJS = (await import("pptxgenjs")).default;
      const p = new PptxGenJS();
      p.layout = "LAYOUT_WIDE";            // 13.33 x 7.5 in
      const slide = p.addSlide();
      slide.background = { color: "FFFFFF" };
      slide.addText(`Topologia do ambiente — ${engagement.name || ""}`, {
        x: 0.4, y: 0.2, w: 12.5, h: 0.5, fontSize: 22, bold: true, color: "052E16" });
      slide.addText(
        `${stats.nodes} ativo(s) · ${stats.edges} conexão(ões)`
        + (stats.orphans ? ` · ${stats.orphans} sem conexão` : "")
        + "  —  cor = risco; tamanho = nº de achados. (Formas editáveis.)",
        { x: 0.4, y: 0.72, w: 12.5, h: 0.3, fontSize: 11, color: "475569" });

      const S = p.ShapeType || PptxGenJS.ShapeType;
      const shapeFor = (t) => ({ ip: S.diamond, service: S.hexagon,
        domain: S.roundRect, host: S.ellipse, subdomain: S.ellipse }[t] || S.ellipse);

      const bb = cy.elements().boundingBox();
      const AX = 0.4, AY = 1.15, AW = 12.5, AH = 5.95;
      const scale = Math.min(AW / (bb.w || 1), AH / (bb.h || 1));
      const offX = AX + (AW - bb.w * scale) / 2;
      const offY = AY + (AH - bb.h * scale) / 2;
      const mx = (x) => offX + (x - bb.x1) * scale;
      const my = (y) => offY + (y - bb.y1) * scale;

      // Conectores (sob os nós).
      cy.edges().forEach((e) => {
        const s = e.source().position(), t = e.target().position();
        const x1 = mx(s.x), y1 = my(s.y), x2 = mx(t.x), y2 = my(t.y);
        slide.addShape(S.line, {
          x: Math.min(x1, x2), y: Math.min(y1, y2),
          w: Math.max(0.01, Math.abs(x2 - x1)), h: Math.max(0.01, Math.abs(y2 - y1)),
          line: { color: "94A3B8", width: 1 },
          flipV: (x2 - x1) * (y2 - y1) < 0,
        });
      });
      // Nós (formas) + rótulos.
      cy.nodes().forEach((n) => {
        const d = n.data(); const pos = n.position();
        const orphan = n.hasClass("orphan");
        const sz = 0.34 + Math.min(0.3, (d.findings || 0) * 0.045);
        const cx = mx(pos.x), cy2 = my(pos.y);
        slide.addShape(shapeFor(d.type), {
          x: cx - sz / 2, y: cy2 - sz / 2, w: sz, h: sz,
          fill: { color: orphan ? "3B2F0A" : (RISK_HEX[d.risk] || "475569") },
          line: orphan ? { color: "F59E0B", width: 1.5, dashType: "dash" }
            : { color: "0B0B0C", width: 0.5 },
        });
        slide.addText(String(d.label || ""), {
          x: cx - 1.0, y: cy2 + sz / 2, w: 2.0, h: 0.22, align: "center",
          fontSize: 7, color: "334155" });
      });
      await p.writeFile({ fileName: `topologia-${_slug}.pptx` });
    } catch (e) { setErr(`Falha ao gerar PPT: ${e.message}`); }
    finally { setBusy(""); }
  }

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
            "label": "data(label)", "color": "#e2e8f0", "font-size": 10,
            "text-valign": "bottom", "text-margin-y": 3,
            "text-background-color": "#0b0b0c", "text-background-opacity": 0.65,
            "text-background-padding": 2, "text-background-shape": "roundrectangle",
            "min-zoomed-font-size": 7,   // esconde rótulos quando afastado (menos poluição)
            "width": (n) => 16 + Math.min(26, (n.data("findings") || 0) * 3),
            "height": (n) => 16 + Math.min(26, (n.data("findings") || 0) * 3),
            "border-width": 1, "border-color": "#0b0b0c",
          },
        },
        { selector: "edge", style: { "width": 1.2, "line-color": "#334155", "curve-style": "bezier", "opacity": 0.55 } },
        // Ativo SEM conexão: destaque (borda tracejada âmbar + halo).
        {
          selector: "node.orphan",
          style: {
            "border-width": 3, "border-color": "#f59e0b", "border-style": "dashed",
            "background-color": "#3b2f0a",
            "color": "#fde68a", "font-weight": "bold",
          },
        },
        { selector: "node:selected", style: { "border-width": 4, "border-color": "#0fdb2b", "border-style": "solid" } },
        { selector: "node.dim", style: { "opacity": 0.25 } },
        { selector: "edge.dim", style: { "opacity": 0.1 } },
      ],
      layout: {
        name: "cose",
        animate: false,
        nodeDimensionsIncludeLabels: true,
        padding: 24,
        componentSpacing: 140,       // separa bem os grupos desconectados
        nodeRepulsion: () => 9000,
        idealEdgeLength: () => 90,
        edgeElasticity: () => 120,
        gravity: 0.3,
        numIter: 1200,
        randomize: true,
      },
      wheelSensitivity: 0.25,
    });
    // Marca ativos sem nenhuma conexão (nós isolados) para destaque visual.
    let orphans = 0;
    cy.nodes().forEach((n) => {
      if (n.degree(false) === 0) { n.addClass("orphan"); orphans++; }
    });
    setStats({ nodes: cy.nodes().length, edges: cy.edges().length, orphans });
    cy.on("tap", "node", (ev) => {
      const node = ev.target;
      const d = node.data();
      // Realça o nó e a vizinhança; escurece o resto (leitura mais fácil).
      cy.elements().addClass("dim");
      node.removeClass("dim");
      node.neighborhood().removeClass("dim");
      node.connectedEdges().removeClass("dim");
      setSel({ id: d.id, type: d.type, risk: d.risk, findings: d.findings,
        items: d.items || [], techs: d.techs || [],
        orphan: node.hasClass("orphan") });
    });
    cy.on("tap", (ev) => {
      if (ev.target === cy) { setSel(null); cy.elements().removeClass("dim"); }
    });
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
          <button className="btn" onClick={load}>Atualizar</button>
        </div>
      </div>

      <div className="row" style={{ gap: 14, fontSize: 12, marginBottom: 6, flexWrap: "wrap" }}>
        {Object.entries(RISK_COLOR).map(([k, c]) => (
          <span key={k}><i style={{ display: "inline-block", width: 10, height: 10, background: c, borderRadius: 2, marginRight: 4 }} />{k}</span>
        ))}
        <span><i style={{ display: "inline-block", width: 10, height: 10, background: "#3b2f0a", border: "2px dashed #f59e0b", borderRadius: 2, marginRight: 4 }} />sem conexão</span>
        <span className="muted">· ◆ IP · ⬡ serviço · ▭ domínio · ○ host/subdomínio</span>
      </div>
      {data && data.nodes.length > 0 && (
        <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>
          {stats.nodes} ativo(s) · {stats.edges} conexão(ões)
          {stats.orphans > 0 && (
            <span style={{ color: "#f59e0b", fontWeight: 700 }}>
              {" "}· ⚠ {stats.orphans} sem conexão</span>
          )}
          {" "}· clique num nó para isolar a vizinhança
        </div>
      )}

      <div ref={boxWrap} style={{ position: "relative", background: "#0b0b0c",
        border: "1px solid var(--line)", borderRadius: 10, overflow: "hidden",
        height: fs ? "100vh" : "62vh" }}>
        <div ref={box} style={{ width: "100%", height: "100%" }} />
        {/* Barra de ferramentas flutuante sobre o grafo (tela preta). */}
        <div className="topoTools">
          <button title="Aproximar" onClick={() => zoomBy(1.3)}>＋</button>
          <button title="Afastar" onClick={() => zoomBy(1 / 1.3)}>－</button>
          <button title="Ajustar à tela" onClick={() => cyRef.current && cyRef.current.fit(undefined, 30)}>⤢</button>
          <button title={fs ? "Sair da tela cheia" : "Tela cheia"} onClick={toggleFs}>{fs ? "✕" : "⛶"}</button>
          <span className="sep" />
          <button title="Exportar imagem PNG" onClick={exportPng}>🖼️ PNG</button>
          <button title="Exportar PowerPoint editável (.pptx)" onClick={exportPpt} disabled={busy === "ppt"}>
            {busy === "ppt" ? "…" : "📊 PPT"}</button>
        </div>
      </div>
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
              {sel.orphan && (
                <span className="pill" style={{ background: "#3b2f0a", color: "#fde68a", border: "1px dashed #f59e0b", fontSize: 10, marginLeft: 6 }}>⚠ SEM CONEXÃO</span>
              )}
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
