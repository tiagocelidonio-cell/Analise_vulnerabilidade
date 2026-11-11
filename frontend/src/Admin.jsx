import React, { useEffect, useState, useCallback } from "react";
import { api } from "./api.js";

export default function Admin({ me }) {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ email: "", name: "", password: "", role: "analyst" });
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");

  const load = useCallback(async () => {
    try { setUsers(await api.listUsers()); } catch (e) { setErr(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function create(e) {
    e.preventDefault(); setErr(""); setMsg("");
    try {
      await api.createUser(form);
      setForm({ email: "", name: "", password: "", role: "analyst" });
      setMsg("Usuário criado.");
      await load();
    } catch (e) { setErr(e.message); }
  }

  async function remove(u) {
    if (!window.confirm(`Excluir o usuário ${u.email}?`)) return;
    try { await api.deleteUser(u.id); await load(); }
    catch (e) { setErr(e.message); }
  }

  async function toggleRole(u) {
    const role = u.role === "admin" ? "analyst" : "admin";
    try { await api.updateUser(u.id, { email: u.email, password: "", role }); await load(); }
    catch (e) { setErr(e.message); }
  }

  return (
    <div>
      <div className="head"><div><h2>Administração — usuários</h2>
        <p className="muted">Cada consultor vê apenas seus clientes; o admin vê todos.</p></div></div>

      <form className="card" onSubmit={create}>
        <h3>Novo usuário</h3>
        <div className="row">
          <input placeholder="E-mail" type="email" value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })} required />
          <input placeholder="Nome" value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </div>
        <div className="row">
          <input placeholder="Senha" type="password" value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })} required />
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="analyst">analyst (consultor)</option>
            <option value="admin">admin</option>
          </select>
          <button className="btn primary" type="submit">Criar</button>
        </div>
        {err && <div className="err">{err}</div>}
        {msg && <div className="info">{msg}</div>}
      </form>

      <table className="t">
        <thead><tr><th>E-mail</th><th>Nome</th><th>Papel</th><th>Ativo</th><th></th></tr></thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td>{u.email}{u.id === me.id && <span className="muted"> (você)</span>}</td>
              <td>{u.name || "—"}</td>
              <td><span className="pill" style={{ background: u.role === "admin" ? "#1f6feb" : "#334155" }}>{u.role}</span></td>
              <td>{u.is_active ? "sim" : "não"}</td>
              <td className="row">
                {u.id !== me.id && (
                  <>
                    <button className="btn" onClick={() => toggleRole(u)}>
                      {u.role === "admin" ? "→ analyst" : "→ admin"}
                    </button>
                    <button className="btn danger" onClick={() => remove(u)}>Excluir</button>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
