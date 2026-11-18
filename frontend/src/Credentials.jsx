import React, { useCallback, useEffect, useState } from "react";
import { api } from "./api.js";

// Biblioteca de credenciais para o ataque de credenciais (gated).
export default function Credentials() {
  const [lists, setLists] = useState([]);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [editing, setEditing] = useState(null); // {id?,name,kind,content}

  const load = useCallback(async () => {
    try { setLists(await api.listWordlists()); } catch (e) { setErr(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  function newList() { setEditing({ name: "", kind: "passwords", content: "" }); }
  async function edit(l) {
    try { setEditing(await api.getWordlist(l.id)); } catch (e) { setErr(e.message); }
  }
  async function save() {
    setErr(""); setMsg("");
    try {
      const body = { name: editing.name, kind: editing.kind, content: editing.content };
      if (editing.id) await api.updateWordlist(editing.id, body);
      else await api.createWordlist(body);
      setEditing(null); setMsg("Lista salva."); await load();
    } catch (e) { setErr(e.message); }
  }
  async function remove(l) {
    if (!window.confirm(`Excluir a lista "${l.name}"?`)) return;
    try { await api.deleteWordlist(l.id); await load(); } catch (e) { setErr(e.message); }
  }
  function dup(l) {
    api.getWordlist(l.id).then((full) =>
      setEditing({ name: full.name + " (cópia)", kind: full.kind, content: full.content }))
      .catch((e) => setErr(e.message));
  }

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <p className="muted" style={{ fontSize: 13 }}>
          Listas de credenciais usadas no <b>Ataque de Credenciais</b> (senhas, usuários
          ou pares <code>user:pass</code>). Escolhidas na hora do scan.
        </p>
        <button className="btn primary" onClick={newList}>+ Nova lista</button>
      </div>
      {err && <div className="err">{err}</div>}
      {msg && <div className="info">{msg}</div>}

      <table className="t">
        <thead><tr><th>Nome</th><th>Tipo</th><th>Itens</th><th>Origem</th><th></th></tr></thead>
        <tbody>
          {lists.map((l) => (
            <tr key={l.id}>
              <td>{l.name}</td>
              <td><span className="pill" style={{ background: "#334155", fontSize: 10 }}>{l.kind}</span></td>
              <td>{l.count}</td>
              <td>{l.builtin ? <span className="pill" style={{ background: "#1c476b", fontSize: 10 }}>público</span> : "própria"}</td>
              <td className="row">
                <button className="btn" onClick={() => dup(l)} title="Duplicar">Duplicar</button>
                {!l.builtin && <button className="btn" onClick={() => edit(l)}>Editar</button>}
                {!l.builtin && <button className="btn danger" onClick={() => remove(l)}>Excluir</button>}
                {l.builtin && <button className="btn" onClick={() => edit(l)}>Ver</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {editing && (
        <div className="modalOverlay" onClick={() => setEditing(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modalHead">
              <h2 style={{ margin: 0 }}>{editing.id ? (editing.builtin ? "Lista pública" : "Editar lista") : "Nova lista"}</h2>
              <button className="btn" onClick={() => setEditing(null)}>✕</button>
            </div>
            <div className="row">
              <input placeholder="Nome" value={editing.name} disabled={editing.builtin}
                onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
              <select value={editing.kind} disabled={editing.builtin}
                onChange={(e) => setEditing({ ...editing, kind: e.target.value })}>
                <option value="passwords">senhas (uma por linha)</option>
                <option value="users">usuários (um por linha)</option>
                <option value="pairs">pares (user:pass por linha)</option>
              </select>
            </div>
            <label className="muted" style={{ fontSize: 12, marginTop: 8, display: "block" }}>
              Conteúdo (uma entrada por linha):
            </label>
            <textarea value={editing.content} disabled={editing.builtin}
              onChange={(e) => setEditing({ ...editing, content: e.target.value })}
              style={{ minHeight: 220, fontFamily: "monospace", fontSize: 12 }} />
            {!editing.builtin && (
              <label className="btn" style={{ cursor: "pointer", marginTop: 6, display: "inline-block", padding: "3px 10px" }}>
                Importar .txt
                <input type="file" accept=".txt,text/plain" style={{ display: "none" }}
                  onChange={(e) => { const f = e.target.files?.[0]; if (!f) return;
                    const rd = new FileReader(); rd.onload = () => setEditing((p) => ({ ...p, content: (p.content ? p.content + "\n" : "") + String(rd.result || "") })); rd.readAsText(f); }} />
              </label>
            )}
            <div className="modalFoot">
              <button className="btn" onClick={() => setEditing(null)}>Fechar</button>
              {!editing.builtin && <button className="btn primary" onClick={save}>Salvar</button>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
