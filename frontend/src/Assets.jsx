import React, { useEffect, useState, useCallback } from "react";
import { api } from "./api.js";

const SEV_COLOR = {
  critical: "#7f1d1d", high: "#b91c1c", medium: "#c2410c",
  low: "#a16207", info: "#334155",
};
const TYPE_LABEL = { hostname: "HOSTNAME", ip: "IP", range: "RANGE" };

export default function Assets({ engagement }) {
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    try { setData(await api.assets(engagement.id)); } catch (e) { setErr(e.message); }
  }, [engagement.id]);
  useEffect(() => { load(); }, [load]);

  if (err) return <div className="err">{err}</div>;
  if (!data) return <div className="muted">Carregando ativos…</div>;

  return (
    <div>
      <div className="head">
        <div>
          <h2>Ativos ({data.total})</h2>
          <p className="muted">Hosts, domínios, IPs e ranges do escopo e descobertos.</p>
        </div>
        <button className="btn" onClick={load}>Atualizar</button>
      </div>

      <table className="t">
        <thead><tr><th>Alvo</th><th>Tipo</th><th>Risco</th><th>Achados</th><th>Scans</th></tr></thead>
        <tbody>
          {data.assets.map((a) => (
            <tr key={a.target}>
              <td>{a.target}</td>
              <td><span className="typeTag">{TYPE_LABEL[a.type] || a.type}</span></td>
              <td><span className="pill" style={{ background: SEV_COLOR[a.risk] }}>{a.risk.toUpperCase()}</span></td>
              <td>{a.findings}</td>
              <td>{a.scans}</td>
            </tr>
          ))}
          {data.assets.length === 0 && <tr><td colSpan={5} className="muted">
            Nenhum ativo. Defina o escopo e rode uma varredura.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}
