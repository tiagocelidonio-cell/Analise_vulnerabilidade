import React, { useState } from "react";
import ToolForm from "./ToolForm.jsx";
import Playbook from "./Playbook.jsx";
import { CATEGORIES } from "./tools.js";

export default function ToolCatalog({ engagement, onRan, onUpdated }) {
  const [openTool, setOpenTool] = useState(null);
  const [msg, setMsg] = useState("");
  const [mode, setMode] = useState("tools"); // tools | guided

  return (
    <div>
      <div className="head"><div>
        <h2>Nova varredura</h2>
        <p className="muted">Escolha uma ferramenta — ou use o scan guiado se não souber por onde começar.</p>
      </div></div>

      <div className="subtabs">
        <button className={`subtab ${mode === "tools" ? "active" : ""}`}
          onClick={() => setMode("tools")}>🧰 Ferramentas</button>
        <button className={`subtab ${mode === "guided" ? "active" : ""}`}
          onClick={() => setMode("guided")}>🧭 Scan guiado (passo a passo)</button>
      </div>

      {mode === "guided" && <Playbook engagement={engagement} onUpdated={onUpdated} />}
      {mode === "tools" && <>

      {msg && <div className="info">{msg}</div>}

      {CATEGORIES.map((c) => (
        <div key={c.cat} style={{ marginTop: 16 }}>
          <h3>{c.cat}</h3>
          <div className="toolGrid">
            {c.items.map((t) => {
              const locked = t.needsIntrusive && !engagement.allow_intrusive;
              return (
                <button key={t.name} className="toolCard" disabled={locked}
                  onClick={() => setOpenTool(t)}>
                  <div className="toolIcon">{t.icon}</div>
                  <div style={{ flex: 1 }}>
                    <div className="toolName">{t.name}</div>
                    <div className="muted" style={{ fontSize: 12 }}>{t.desc}</div>
                    {locked && (
                      <div style={{ fontSize: 11, color: "#a16207" }}>
                        ative "sondas intrusivas" no cliente
                      </div>
                    )}
                  </div>
                  <span className="muted" style={{ fontSize: 12 }}>Configurar ▸</span>
                </button>
              );
            })}
          </div>
        </div>
      ))}

      {openTool && (
        <ToolForm engagement={engagement} tool={openTool}
          onClose={() => setOpenTool(null)}
          onUpdated={onUpdated}
          onRan={(m) => { setMsg(m); onRan && onRan(); }} />
      )}
      </>}
    </div>
  );
}
