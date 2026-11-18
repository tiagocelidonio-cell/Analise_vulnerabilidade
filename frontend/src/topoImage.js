// Captura uma imagem PNG da topologia a partir dos dados, SEM depender da tela
// (renderiza um cytoscape off-screen). Usado para embutir o desenho no relatório.
import cytoscape from "cytoscape";

const RISK_COLOR = {
  critical: "#7f1d1d", high: "#b91c1c", medium: "#c2410c", low: "#a16207", info: "#475569",
};
const TYPE_SHAPE = {
  domain: "round-rectangle", subdomain: "ellipse", host: "ellipse",
  ip: "diamond", service: "hexagon",
};

export async function captureTopologyPng(data) {
  if (!data || !Array.isArray(data.nodes) || data.nodes.length === 0) return null;
  const div = document.createElement("div");
  div.style.cssText = "position:fixed;left:-99999px;top:0;width:1600px;height:1000px;";
  document.body.appendChild(div);
  try {
    const elements = [
      ...data.nodes.map((n) => ({
        data: { id: n.id, label: n.label, type: n.type, risk: n.risk, findings: n.findings },
      })),
      ...data.edges.map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target } })),
    ];
    const cy = cytoscape({
      container: div,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": (n) => RISK_COLOR[n.data("risk")] || "#475569",
            "shape": (n) => TYPE_SHAPE[n.data("type")] || "ellipse",
            "label": "data(label)", "color": "#e2e8f0", "font-size": 11,
            "text-valign": "bottom", "text-margin-y": 3,
            "text-background-color": "#0b0b0c", "text-background-opacity": 0.65,
            "text-background-padding": 2, "text-background-shape": "roundrectangle",
            "width": (n) => 16 + Math.min(26, (n.data("findings") || 0) * 3),
            "height": (n) => 16 + Math.min(26, (n.data("findings") || 0) * 3),
            "border-width": 1, "border-color": "#0b0b0c",
          },
        },
        { selector: "edge", style: { "width": 1.2, "line-color": "#334155", "curve-style": "bezier", "opacity": 0.55 } },
        {
          selector: "node.orphan",
          style: {
            "border-width": 3, "border-color": "#f59e0b", "border-style": "dashed",
            "background-color": "#3b2f0a", "color": "#fde68a",
          },
        },
      ],
      layout: {
        name: "cose", animate: false, nodeDimensionsIncludeLabels: true,
        padding: 24, componentSpacing: 140, nodeRepulsion: () => 9000,
        idealEdgeLength: () => 90, edgeElasticity: () => 120, gravity: 0.3,
        numIter: 1200, randomize: true,
      },
    });
    cy.nodes().forEach((n) => { if (n.degree(false) === 0) n.addClass("orphan"); });
    cy.fit(undefined, 30);
    const png = cy.png({ full: true, scale: 2, bg: "#0b0b0c" });
    cy.destroy();
    return png;
  } catch {
    return null;
  } finally {
    div.remove();
  }
}
