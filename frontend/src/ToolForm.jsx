import React, { useState } from "react";
import { api } from "./api.js";

// Portas do modo "Light" (rápido). "Completo" usa o padrão do servidor (todas).
const LIGHT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389,
  5432, 8080, 8443, 502, 102, 1883];

export default function ToolForm({ engagement, tool, onClose, onRan, onUpdated }) {
  const isExploit = tool.exploit !== undefined;
  const isPortTool = (tool.collectors || []).includes("port_scan");

  const [target, setTarget] = useState((engagement.scope || []).join(" "));
  const [scanType, setScanType] = useState("light");
  const [customPorts, setCustomPorts] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [outOfScope, setOutOfScope] = useState(null);

  const targetList = () => target.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

  function portsForRun() {
    if (!isPortTool) return [];
    if (customPorts.trim()) {
      return customPorts.split(/[\s,]+/).map((p) => parseInt(p, 10)).filter((n) => !isNaN(n));
    }
    return scanType === "light" ? LIGHT_PORTS : [];
  }

  async function start(addToScope = false) {
    setErr(""); setOutOfScope(null); setBusy(true);
    try {
      if (addToScope) {
        const novo = [...new Set([...(engagement.scope || []), ...targetList()])];
        const upd = await api.updateEngagement(engagement.id, { scope: novo });
        onUpdated && onUpdated(upd);
      }
      if (isExploit) {
        const r = await api.validate(engagement.id, tool.exploit);
        onRan && onRan(`${tool.name}: ${r.confirmed} confirmada(s) em ${r.tested_targets} alvo(s).`);
      } else {
        await api.createScan(engagement.id, {
          targets: targetList(), ports: portsForRun(), collectors: tool.collectors,
        });
        onRan && onRan(`${tool.name} iniciada.`);
      }
      onClose();
    } catch (e) {
      // Alvo fora do escopo -> oferece cadastrar o ativo no escopo.
      if (/fora do escopo/i.test(e.message)) {
        setOutOfScope(e.message);
      } else {
        setErr(e.message);
      }
    } finally { setBusy(false); }
  }

  return (
    <div className="modalOverlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modalHead">
          <h2 style={{ margin: 0 }}>{tool.icon} {tool.name}</h2>
          <button className="btn" onClick={onClose}>✕</button>
        </div>
        <p className="muted">{tool.desc}</p>

        {isExploit ? (
          <div className="info">
            Valida as falhas já encontradas nos serviços web (fases anteriores).
            Não-destrutivo.
          </div>
        ) : (
          <>
            <label className="muted" style={{ fontSize: 12 }}>Alvo(s)</label>
            <input autoFocus value={target} onChange={(e) => setTarget(e.target.value)}
              placeholder="ex: cliente.com.br  10.0.0.0/24  1.2.3.4" />

            <div className="row" style={{ gap: 18, marginTop: 10 }}>
              <span className="muted" style={{ fontSize: 13 }}>Tipo:</span>
              <label className="check"><input type="radio" checked={scanType === "light"}
                onChange={() => setScanType("light")} /> Rápido</label>
              <label className="check"><input type="radio" checked={scanType === "full"}
                onChange={() => setScanType("full")} /> Completo</label>
            </div>

            {isPortTool && (
              <div style={{ marginTop: 8 }}>
                <label className="muted" style={{ fontSize: 12 }}>Portas (opcional — vazio usa o padrão)</label>
                <input value={customPorts} onChange={(e) => setCustomPorts(e.target.value)}
                  placeholder="ex: 80, 443, 8080, 502" />
              </div>
            )}
          </>
        )}

        {err && <div className="err" style={{ marginTop: 10 }}>{err}</div>}
        {outOfScope && (
          <div className="err" style={{ marginTop: 10 }}>
            {outOfScope}
            <div style={{ marginTop: 8 }}>
              <button className="btn primary" disabled={busy} onClick={() => start(true)}>
                Adicionar ao escopo e escanear
              </button>
            </div>
          </div>
        )}

        <div className="modalFoot">
          <button className="btn" onClick={onClose}>Cancelar</button>
          <button className="btn primary" disabled={busy} onClick={() => start(false)}>
            {busy ? "Iniciando…" : "▶ Iniciar scan"}
          </button>
        </div>
      </div>
    </div>
  );
}
