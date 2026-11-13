import React, { useEffect, useState, useCallback, useRef } from "react";
import { api } from "./api.js";
import { fmtDateTime } from "./branding.js";

const STATE_LABEL = {
  idle: "ocioso", connecting: "conectando…", downloading: "baixando",
  done: "concluído", error: "erro", cancelled: "cancelado",
};
const STATE_COLOR = {
  connecting: "#a16207", downloading: "var(--accent)", done: "#15803d",
  error: "#b91c1c", cancelled: "#334155", idle: "var(--muted)",
};

export default function CveBase() {
  const [st, setSt] = useState(null);
  const [sched, setSched] = useState(null);
  const [msg, setMsg] = useState("");
  const timer = useRef(null);

  const load = useCallback(async () => {
    try {
      const s = await api.cveStatus();
      setSt(s);
      if (s.schedule) setSched((prev) => prev || s.schedule);
    } catch (e) { setMsg(e.message); }
  }, []);

  useEffect(() => {
    load();
    // Poll contínuo enquanto o download estiver rodando.
    timer.current = setInterval(load, 2500);
    return () => clearInterval(timer.current);
  }, [load]);

  async function update(full) {
    setMsg(full ? "Iniciando download da base completa…" : "Atualizando CVEs vistos…");
    try {
      const r = await api.cveUpdate(full);
      setMsg(r.mensagem || "Atualização iniciada.");
      setTimeout(load, 1200);
    } catch (e) { setMsg(`Falha: ${e.message}`); }
  }
  async function cancelImport() {
    try { await api.cveImportCancel(); setMsg("Cancelamento solicitado…"); setTimeout(load, 1000); }
    catch (e) { setMsg(`Falha: ${e.message}`); }
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
  const imp = st.import || { state: "idle", percent: 0 };
  const running = imp.running;

  return (
    <div className="card" style={{ maxWidth: 680 }}>
      <h3>Base de CVEs</h3>
      <div className="muted" style={{ fontSize: 13, marginBottom: 10 }}>
        Local: <b>{st.count}</b> CVEs
        {" · "}última atualização: <b>{st.last_updated ? fmtDateTime(st.last_updated) : "nunca"}</b>
      </div>

      {/* ---- Monitor do download ---- */}
      <div className="cveopt">
        <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
          <b style={{ fontSize: 13 }}>Status do download</b>
          <span className="status" style={{ background: STATE_COLOR[imp.state] || "#334155", color: "#fff" }}>
            {STATE_LABEL[imp.state] || imp.state}
          </span>
        </div>
        {(running || imp.state === "done" || imp.state === "cancelled" || imp.state === "error") && (
          <>
            <div className="progwrap" style={{ marginTop: 8 }}>
              <div className="bartrack" style={{ flex: 1 }}>
                <div className="barfill" style={{
                  width: `${imp.percent || 0}%`,
                  background: STATE_COLOR[imp.state] || "var(--accent)" }} />
              </div>
              <span className="muted" style={{ fontSize: 11, whiteSpace: "nowrap" }}>{imp.percent || 0}%</span>
            </div>
            <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
              {imp.phase || STATE_LABEL[imp.state]}
              {imp.total ? ` · ${imp.processed}/${imp.total} CVEs` : ""}
              {imp.source ? ` · ${imp.source}` : ""}
            </div>
            {imp.updated_at && (
              <div className="muted" style={{ fontSize: 11 }}>
                {running ? "atualizado" : "finalizado"} {fmtDateTime(imp.finished_at || imp.updated_at)}
              </div>
            )}
          </>
        )}
        {imp.state === "error" && imp.error && (
          <div className="err" style={{ marginTop: 6, fontSize: 12 }}>⚠ {imp.error}</div>
        )}
        {running && (
          <div className="row" style={{ marginTop: 8 }}>
            <button className="btn danger" style={{ padding: "3px 12px" }} onClick={cancelImport}>⏹ Parar download</button>
          </div>
        )}
      </div>

      {/* ---- Ações manuais ---- */}
      <div className="cveopt">
        <b style={{ fontSize: 13 }}>Atualização manual</b>
        <div className="row" style={{ gap: 8, marginTop: 6, flexWrap: "wrap" }}>
          <button className="btn" onClick={() => update(false)} disabled={running}>↻ Atualizar CVEs vistos</button>
          <button className="btn primary" onClick={() => update(true)} disabled={running}
            title="Baixa a base completa pela API oficial da NVD (paginada, com progresso).">
            ⬇ Baixar base completa (NVD)
          </button>
        </div>
        <p className="muted" style={{ fontSize: 11, marginTop: 4 }}>
          Sem chave da NVD o download é lento (limite de 5 req/30s). Configure
          <b> NVD_API_KEY</b> no .env para acelerar (gratuita).
        </p>
      </div>

      {/* ---- Rotina programada ---- */}
      <div className="cveopt">
        <b style={{ fontSize: 13 }}>Atualização programada</b>
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
              <option value="full">Base completa (NVD)</option>
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
