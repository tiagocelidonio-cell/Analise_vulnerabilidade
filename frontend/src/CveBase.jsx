import React, { useEffect, useState, useCallback } from "react";
import { api } from "./api.js";
import { fmtDateTime } from "./branding.js";

// Administração da Base de CVEs: status + atualização manual + rotina agendada.
export default function CveBase() {
  const [st, setSt] = useState(null);
  const [sched, setSched] = useState(null);
  const [msg, setMsg] = useState("");

  const load = useCallback(async () => {
    try {
      const s = await api.cveStatus();
      setSt(s);
      if (s.schedule) setSched((prev) => prev || s.schedule);
    } catch (e) { setMsg(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function update(full) {
    setMsg(full ? "Importando base completa (pode demorar)…" : "Atualizando CVEs vistos…");
    try {
      const r = await api.cveUpdate(full);
      setMsg(r.mensagem || "Atualização iniciada.");
      setTimeout(load, 4000);
    } catch (e) { setMsg(`Falha: ${e.message}`); }
  }
  async function saveSchedule() {
    try {
      const saved = await api.cveScheduleSet({
        enabled: sched.enabled,
        interval_hours: Number(sched.interval_hours) || 24,
        full: sched.full,
      });
      setSched(saved);
      setMsg(saved.enabled
        ? `Rotina salva: a cada ${saved.interval_hours}h (${saved.full ? "base completa" : "CVEs vistos"}).`
        : "Rotina desativada.");
    } catch (e) { setMsg(`Falha ao salvar rotina: ${e.message}`); }
  }

  if (!st) return <div className="muted">Carregando…</div>;

  return (
    <div className="card" style={{ maxWidth: 640 }}>
      <h3>Base de CVEs</h3>
      <div className="muted" style={{ fontSize: 13, marginBottom: 6 }}>
        Local: <b>{st.count}</b> CVEs
        {" · "}última atualização: <b>{st.last_updated ? fmtDateTime(st.last_updated) : "nunca"}</b>
      </div>

      <div className="cveopt">
        <b style={{ fontSize: 13 }}>1 · Atualização manual</b>
        <div className="row" style={{ gap: 8, marginTop: 6, flexWrap: "wrap" }}>
          <button className="btn" onClick={() => update(false)}>↻ Atualizar CVEs vistos</button>
          <button className="btn" onClick={() => update(true)}
            title="Baixa o bundle oficial (CVE List JSON 5.0). Pesado.">⬇ Importar base completa</button>
        </div>
      </div>

      <div className="cveopt">
        <b style={{ fontSize: 13 }}>2 · Atualização programada</b>
        {sched ? (
          <div className="row" style={{ gap: 10, marginTop: 6, flexWrap: "wrap", alignItems: "center" }}>
            <label className="check">
              <input type="checkbox" checked={sched.enabled}
                onChange={(e) => setSched({ ...sched, enabled: e.target.checked })} /> Ativar rotina
            </label>
            <span className="muted" style={{ fontSize: 12 }}>a cada</span>
            <input type="number" min="1" value={sched.interval_hours} style={{ width: 70 }}
              onChange={(e) => setSched({ ...sched, interval_hours: e.target.value })} />
            <span className="muted" style={{ fontSize: 12 }}>horas</span>
            <select value={sched.full ? "full" : "seen"} style={{ width: "auto" }}
              onChange={(e) => setSched({ ...sched, full: e.target.value === "full" })}>
              <option value="seen">CVEs vistos (leve)</option>
              <option value="full">Base completa (pesado)</option>
            </select>
            <button className="btn primary" onClick={saveSchedule}>Salvar rotina</button>
          </div>
        ) : <div className="muted">carregando…</div>}
        {sched?.last_run && (
          <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>
            Última execução automática: {fmtDateTime(sched.last_run)}
            {sched.last_result && ` — ${sched.last_result}`}
          </div>
        )}
      </div>

      {msg && <div className="info" style={{ fontSize: 12, marginTop: 8 }}>{msg}</div>}
    </div>
  );
}
