import React, { useEffect, useRef, useState } from "react";
import { api } from "./api.js";

// Terminal ao vivo do scan: mostra EXATAMENTE o que está sendo executado
// (comandos reais, lotes, resultados e erros), estilo console Linux.
const LEVEL_COLOR = { info: "#d1d5db", warn: "#fbbf24", error: "#f87171" };

export default function ScanConsole({ scanId }) {
  const [log, setLog] = useState([]);
  const [err, setErr] = useState("");
  const boxRef = useRef(null);
  const timer = useRef(null);
  const pinned = useRef(true); // auto-scroll só se o usuário está no fim

  useEffect(() => {
    let alive = true;
    async function tick() {
      try {
        const r = await api.scanLog(scanId);
        if (!alive) return;
        setLog(r.log || []);
        if (!["queued", "running", "paused"].includes(r.status)) {
          clearInterval(timer.current); // terminou: para de pollar
        }
      } catch (e) { if (alive) setErr(e.message); }
    }
    tick();
    timer.current = setInterval(tick, 1500);
    return () => { alive = false; clearInterval(timer.current); };
  }, [scanId]);

  useEffect(() => {
    const el = boxRef.current;
    if (el && pinned.current) el.scrollTop = el.scrollHeight;
  }, [log]);

  function onScroll() {
    const el = boxRef.current;
    if (!el) return;
    pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  }

  return (
    <div ref={boxRef} onScroll={onScroll} style={{
      background: "#0a0e14", border: "1px solid #1f2937", borderRadius: 6,
      margin: "4px 0 8px", padding: "8px 10px", maxHeight: 320, overflow: "auto",
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", fontSize: 12,
    }}>
      <div style={{ color: "#4b5563", marginBottom: 4, fontSize: 11 }}>
        ● execução ao vivo — scan {scanId.slice(0, 8)}
      </div>
      {err && <div style={{ color: "#f87171" }}>erro ao ler log: {err}</div>}
      {log.length === 0 && !err && <div style={{ color: "#6b7280" }}>aguardando saída…</div>}
      {log.map((l, i) => (
        <div key={i} style={{
          color: LEVEL_COLOR[l.level] || "#d1d5db",
          whiteSpace: "pre-wrap", wordBreak: "break-all", lineHeight: 1.5,
        }}>
          <span style={{ color: "#4b5563" }}>
            {l.ts ? new Date(l.ts).toLocaleTimeString() : ""}{" "}
          </span>
          {l.msg}
        </div>
      ))}
    </div>
  );
}
