import React, { useEffect, useState, useCallback, useRef } from "react";
import { api } from "./api.js";
import { fmtDateTime } from "./branding.js";

const KINDS = [
  { v: "nda", l: "NDA (confidencialidade)" },
  { v: "authorization", l: "Termo de Autorização / Escopo" },
  { v: "goocj", l: "Carta de autorização (get out of jail)" },
  { v: "prior_report", l: "Relatório anterior / contexto" },
  { v: "other", l: "Outro" },
];
const KIND_LABEL = Object.fromEntries(KINDS.map((k) => [k.v, k.l]));

function human(size) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(0)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

export default function Documents({ engagement }) {
  const [docs, setDocs] = useState(null);
  const [kind, setKind] = useState("nda");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const fileRef = useRef(null);

  const load = useCallback(async () => {
    try { setDocs(await api.listDocuments(engagement.id)); } catch (e) { setErr(e.message); }
  }, [engagement.id]);
  useEffect(() => { load(); }, [load]);

  async function onFile(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    setErr(""); setBusy(true);
    try { await api.uploadDocument(engagement.id, f, kind); await load(); }
    catch (ex) { setErr(ex.message); }
    finally { setBusy(false); if (fileRef.current) fileRef.current.value = ""; }
  }
  async function remove(d) {
    if (!window.confirm(`Excluir o documento "${d.filename}"?`)) return;
    try { await api.deleteDocument(d.id); await load(); } catch (e) { setErr(e.message); }
  }

  const has = (k) => docs?.some((d) => d.kind === k);

  return (
    <div>
      <div className="head"><div>
        <h2>Documentos do engagement</h2>
        <p className="muted">NDA, autorização e anexos — para auditoria e relatório. Opcionais.</p>
      </div></div>

      {/* Checklist de governança */}
      <div className="card">
        <h3>Governança</h3>
        <div className="row" style={{ gap: 16, flexWrap: "wrap" }}>
          <span>{has("nda") ? "✅" : "⚠️"} NDA</span>
          <span>{has("authorization") ? "✅" : "⚠️"} Autorização</span>
          <span className="muted" style={{ fontSize: 12 }}>
            {engagement.allow_exploitation
              ? "Exploração habilitada — recomenda-se NDA + autorização anexados."
              : "Exploração desabilitada neste engagement."}
          </span>
        </div>
      </div>

      <div className="card">
        <h3>Enviar documento</h3>
        <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <select value={kind} onChange={(e) => setKind(e.target.value)} style={{ width: "auto" }}>
            {KINDS.map((k) => <option key={k.v} value={k.v}>{k.l}</option>)}
          </select>
          <label className="btn" style={{ cursor: "pointer" }}>
            {busy ? "Enviando…" : "Selecionar arquivo (PDF, até 15 MB)"}
            <input ref={fileRef} type="file" style={{ display: "none" }} onChange={onFile} disabled={busy} />
          </label>
        </div>
        {err && <div className="err" style={{ marginTop: 8 }}>{err}</div>}
      </div>

      <table className="t">
        <thead><tr><th>Tipo</th><th>Arquivo</th><th>Tamanho</th><th>Enviado por</th><th>Data</th><th></th></tr></thead>
        <tbody>
          {(docs || []).map((d) => (
            <tr key={d.id}>
              <td>{KIND_LABEL[d.kind] || d.kind}</td>
              <td>{d.filename}</td>
              <td>{human(d.size)}</td>
              <td className="muted">{d.uploaded_by || "—"}</td>
              <td className="muted" style={{ fontSize: 12 }}>{fmtDateTime(d.uploaded_at)}</td>
              <td className="row" style={{ gap: 6, justifyContent: "flex-end" }}>
                <a className="btn" href={api.documentUrl(d.id)} target="_blank" rel="noreferrer">Abrir</a>
                <button className="btn danger" onClick={() => remove(d)}>Excluir</button>
              </td>
            </tr>
          ))}
          {docs && docs.length === 0 && <tr><td colSpan={6} className="muted">Nenhum documento anexado.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}
