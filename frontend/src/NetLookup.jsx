import React, { useState } from "react";
import { api } from "./api.js";

function Chips({ items, color = "#1c476b" }) {
  if (!items || items.length === 0) return <span className="muted">—</span>;
  return (
    <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
      {items.map((t, i) => (
        <span key={i} className="pill" style={{ background: color, fontSize: 11 }}>{t}</span>
      ))}
    </div>
  );
}

function RecordRows({ recs }) {
  const order = ["A", "AAAA", "CNAME", "www_CNAME", "MX", "NS", "TXT", "SOA", "CAA", "DMARC"];
  return (
    <table className="t">
      <thead><tr><th style={{ width: 110 }}>Tipo</th><th>Registros</th></tr></thead>
      <tbody>
        {order.map((k) => {
          const v = recs[k];
          if (!v || (Array.isArray(v) && v.length === 0)) return null;
          return (
            <tr key={k}>
              <td style={{ fontWeight: 600 }}>{k.replace("www_", "www ")}</td>
              <td style={{ wordBreak: "break-all", fontSize: 12 }}>
                {(Array.isArray(v) ? v : [v]).map((x, i) => <div key={i}>{x}</div>)}
              </td>
            </tr>
          );
        })}
        {recs.PTR && Object.keys(recs.PTR).length > 0 && (
          <tr><td style={{ fontWeight: 600 }}>PTR (reverso)</td>
            <td style={{ fontSize: 12 }}>
              {Object.entries(recs.PTR).map(([ip, p]) => <div key={ip}>{ip} → {p}</div>)}
            </td></tr>
        )}
      </tbody>
    </table>
  );
}

export default function NetLookup() {
  const [target, setTarget] = useState("");
  const [res, setRes] = useState(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function run(e) {
    e?.preventDefault();
    setErr(""); setRes(null);
    const t = target.trim();
    if (!t) return;
    setBusy(true);
    try { setRes(await api.netlookup(t)); }
    catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  const Bool = ({ v, yes = "sim", no = "não" }) => (
    <span style={{ color: v ? "#15803d" : "#b91c1c", fontWeight: 700 }}>{v ? yes : no}</span>
  );

  return (
    <div>
      <div className="head"><div>
        <h2>Rede / DNS</h2>
        <p className="muted">Consulta passiva (DNS + cabeçalhos): registros, hospedagem,
          CDN/WAF e segurança de e-mail. Informação pública — não faz varredura.</p>
      </div></div>

      <form className="card" onSubmit={run}>
        <div className="row">
          <input placeholder="Domínio (ex.: cliente.com.br)" value={target}
            autoFocus onChange={(e) => setTarget(e.target.value)} />
          <button className="btn primary" type="submit" disabled={busy}>
            {busy ? "Consultando…" : "Consultar"}</button>
        </div>
        {err && <div className="err" style={{ marginTop: 8 }}>{err}</div>}
      </form>

      {res && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Onde está hospedado</h3>
            <table className="t"><tbody>
              <tr><td style={{ width: 200, fontWeight: 600 }}>Hospedagem</td>
                <td><Chips items={res.hosting} color="#1f6feb" /></td></tr>
              <tr><td style={{ fontWeight: 600 }}>Provedor de DNS</td>
                <td><Chips items={res.dns_provider} color="#6d28d9" /></td></tr>
              <tr><td style={{ fontWeight: 600 }}>CDN / WAF</td>
                <td><Chips items={res.cdn_waf?.detected} color="#b45309" /></td></tr>
              {res.cdn_waf?.server && (
                <tr><td style={{ fontWeight: 600 }}>Servidor (header)</td>
                  <td style={{ fontSize: 12 }}>{res.cdn_waf.server}</td></tr>)}
            </tbody></table>
            {res.cdn_waf?.headers && Object.keys(res.cdn_waf.headers).length > 0 && (
              <details style={{ marginTop: 6 }}>
                <summary className="muted" style={{ fontSize: 12, cursor: "pointer" }}>Cabeçalhos reveladores</summary>
                <table className="t"><tbody>
                  {Object.entries(res.cdn_waf.headers).map(([k, v]) => (
                    <tr key={k}><td style={{ fontWeight: 600, width: 200 }}>{k}</td>
                      <td style={{ fontSize: 12, wordBreak: "break-all" }}>{v}</td></tr>
                  ))}
                </tbody></table>
              </details>
            )}
          </div>

          <div className="card">
            <h3 style={{ marginTop: 0 }}>Segurança de e-mail</h3>
            <table className="t"><tbody>
              <tr><td style={{ width: 200, fontWeight: 600 }}>Gateway de e-mail (MX)</td>
                <td><Chips items={res.email_security?.gateways} color="#0f766e" /></td></tr>
              <tr><td style={{ fontWeight: 600 }}>Provedores no SPF</td>
                <td><Chips items={res.email_security?.spf_providers} color="#0f766e" /></td></tr>
              <tr><td style={{ fontWeight: 600 }}>SPF</td><td><Bool v={res.posture?.spf} /></td></tr>
              <tr><td style={{ fontWeight: 600 }}>DMARC</td>
                <td><Bool v={res.posture?.dmarc} />
                  {res.posture?.dmarc_policy && <span className="muted" style={{ fontSize: 12 }}> · política: p={res.posture.dmarc_policy}</span>}</td></tr>
              <tr><td style={{ fontWeight: 600 }}>Monitoramento DMARC</td>
                <td><Chips items={res.security_tools?.dmarc_monitoring} color="#334155" /></td></tr>
            </tbody></table>
          </div>

          <div className="card">
            <h3 style={{ marginTop: 0 }}>Ferramentas / serviços detectados</h3>
            <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
              Verificações de domínio (TXT) que indicam serviços em uso.</p>
            <Chips items={res.security_tools?.verifications} color="#475569" />
            <div className="row" style={{ gap: 20, marginTop: 10, flexWrap: "wrap" }}>
              <span>CAA: <Bool v={res.posture?.caa} /></span>
              <span>DNSSEC: <Bool v={res.posture?.dnssec} /></span>
            </div>
          </div>

          <div className="card">
            <h3 style={{ marginTop: 0 }}>Registros DNS</h3>
            <RecordRows recs={res.records} />
          </div>
        </div>
      )}
    </div>
  );
}
