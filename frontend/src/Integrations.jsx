import React, { useEffect, useState, useCallback } from "react";
import { api } from "./api.js";

// Chaves de API / integrações: status, edição e ajuda de como obter cada uma.
export default function Integrations() {
  const [items, setItems] = useState(null);
  const [vals, setVals] = useState({});   // {field: novo valor digitado}
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [helpOpen, setHelpOpen] = useState({});

  const load = useCallback(async () => {
    try { setItems((await api.getIntegrations()).integrations); }
    catch (e) { setErr(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function saveOne(it) {
    setMsg(""); setErr("");
    const updates = {};
    for (const f of it.fields) {
      if (vals[f.name] !== undefined) updates[f.name] = vals[f.name];
    }
    if (!Object.keys(updates).length) { setMsg("Nada para salvar."); return; }
    try {
      const r = await api.updateIntegrations(updates);
      setItems(r.integrations);
      setVals((v) => { const n = { ...v }; for (const k of Object.keys(updates)) delete n[k]; return n; });
      setMsg(`${it.label}: salvo.`);
    } catch (e) { setErr(e.message); }
  }
  async function clearField(name, label) {
    if (!window.confirm(`Remover a chave "${label}"?`)) return;
    try { const r = await api.updateIntegrations({ [name]: "" }); setItems(r.integrations); setMsg("Chave removida."); }
    catch (e) { setErr(e.message); }
  }

  if (err && !items) return <div className="err">{err}</div>;
  if (!items) return <div className="muted">Carregando…</div>;

  return (
    <div>
      <p className="muted" style={{ marginTop: 0 }}>
        Chaves de API das integrações. Todas são <b>opcionais</b> — o sistema funciona
        sem elas (com recursos reduzidos). O valor nunca é exibido depois de salvo.
      </p>

      {items.map((it) => (
        <div key={it.id} className="card" style={{ maxWidth: 680 }}>
          <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
            <h3 style={{ margin: 0 }}>
              {it.label}{" "}
              <span className="status" style={{ background: it.configured ? "#14532d" : "#334155",
                color: it.configured ? "#bbf7d0" : "#cbd5e1", marginLeft: 6 }}>
                {it.configured ? "configurada" : "não configurada"}
              </span>
            </h3>
            <button className="topbtn" title="Como obter" style={{ border: "1px solid var(--line)" }}
              onClick={() => setHelpOpen((h) => ({ ...h, [it.id]: !h[it.id] }))}>?</button>
          </div>

          {helpOpen[it.id] && (
            <div className="info" style={{ fontSize: 13 }}>
              {it.help}
              {it.link && <div style={{ marginTop: 6 }}>
                <a href={it.link} target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>
                  Obter chave / instruções ↗
                </a>
              </div>}
            </div>
          )}

          {it.fields.map((f) => (
            <div key={f.name} style={{ marginTop: 8 }}>
              <label className="muted" style={{ fontSize: 12 }}>
                {f.label} {f.configured && <span style={{ color: "#15803d" }}>• configurada</span>}
              </label>
              <div className="row" style={{ gap: 8 }}>
                <input type="password" autoComplete="new-password"
                  placeholder={f.configured ? "•••••••• (deixe em branco para manter)" : "colar a chave"}
                  value={vals[f.name] ?? ""}
                  onChange={(e) => setVals((v) => ({ ...v, [f.name]: e.target.value }))} />
                {f.configured && (
                  <button className="btn" onClick={() => clearField(f.name, f.label)}>Remover</button>
                )}
              </div>
            </div>
          ))}

          <div className="row" style={{ marginTop: 10 }}>
            <button className="btn primary" onClick={() => saveOne(it)}>Salvar</button>
          </div>
        </div>
      ))}

      {msg && <div className="info">{msg}</div>}
      {err && <div className="err">{err}</div>}
    </div>
  );
}
