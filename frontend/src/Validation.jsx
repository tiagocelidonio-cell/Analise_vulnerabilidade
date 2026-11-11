import React, { useState } from "react";
import { api } from "./api.js";

const TIER_COLOR = { safe: "#15803d", intrusive: "#c2410c" };

export default function Validation({ engagement }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [log, setLog] = useState([]);
  const [summary, setSummary] = useState(null);

  async function run(intrusive) {
    if (intrusive && !window.confirm(
      "Validação INTRUSIVA: envia entradas manipuladas (SQLi/XSS/redirect/LFI) " +
      "de forma NÃO-destrutiva. Confirme que há autorização por escrito do cliente."
    )) return;
    setBusy(true); setMsg(""); setLog([]); setSummary(null);
    try {
      const r = await api.validate(engagement.id, intrusive);
      setLog(r.log || []);
      setSummary(r);
      setMsg(`Concluído: ${r.confirmed} confirmada(s) em ${r.tested_targets} alvo(s).`);
    } catch (e) { setMsg(e.message); }
    finally { setBusy(false); }
  }

  return (
    <div>
      <div className="head">
        <div>
          <h2>Validação de vulnerabilidades</h2>
          <p className="muted">
            Prova não-destrutiva. Sem testes de indisponibilidade (DoS).
          </p>
        </div>
        <div className="row">
          <button className="btn primary" onClick={() => run(false)} disabled={busy}>
            {busy ? "Executando…" : "Executar SAFE"}
          </button>
          {engagement.allow_intrusive && (
            <button className="btn danger" onClick={() => run(true)} disabled={busy}>
              Executar INTRUSIVE
            </button>
          )}
        </div>
      </div>

      {!engagement.allow_intrusive && (
        <div className="info">
          Sondas intrusivas desativadas. Ative "Permitir sondas intrusivas" no cadastro do cliente.
        </div>
      )}
      {msg && <div className="info">{msg}</div>}

      <div className="card">
        <h3>O que foi executado (evidências)</h3>
        {log.length === 0 && (
          <p className="muted">
            {busy ? "Executando sondas…"
              : "Clique em Executar para rodar as sondas e ver os comandos e provas."}
          </p>
        )}
        {log.map((e, i) => (
          <div key={i} className="probe">
            <div className="row" style={{ justifyContent: "space-between" }}>
              <div>
                <span className="pill" style={{ background: TIER_COLOR[e.tier] || "#334155" }}>
                  {e.tier.toUpperCase()}
                </span>
                <b style={{ marginLeft: 8 }}>{e.probe}</b> — {e.target}
              </div>
              <span className="muted">{e.severity}</span>
            </div>
            <p style={{ margin: "6px 0" }}>{e.note}</p>
            {e.command && <pre className="cmd">$ {e.command}</pre>}
            {e.proof && <pre className="evi">{e.proof}</pre>}
          </div>
        ))}
      </div>

      <p className="muted" style={{ fontSize: 12 }}>
        Cada confirmação também vira um achado (confiança 100%) com a evidência anexada,
        visível no Dashboard, na aba Operação e no relatório PDF.
      </p>
    </div>
  );
}
