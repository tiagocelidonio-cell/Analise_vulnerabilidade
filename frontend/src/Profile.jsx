import React, { useState } from "react";
import { api } from "./api.js";

// Modal de perfil: dados pessoais + troca de senha (qualquer usuário).
export default function Profile({ user, onClose, onSaved }) {
  const [name, setName] = useState(user.name || "");
  const [email, setEmail] = useState(user.email || "");
  const [cur, setCur] = useState("");
  const [pw1, setPw1] = useState("");
  const [pw2, setPw2] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function saveInfo() {
    setErr(""); setMsg(""); setBusy(true);
    try {
      const u = await api.updateMe({ name, email });
      onSaved && onSaved(u);
      setMsg("Dados atualizados.");
    } catch (e) { setErr(e.message); } finally { setBusy(false); }
  }

  async function savePassword() {
    setErr(""); setMsg("");
    if (pw1 !== pw2) { setErr("A confirmação não confere."); return; }
    if (pw1.length < 6) { setErr("A nova senha deve ter ao menos 6 caracteres."); return; }
    setBusy(true);
    try {
      await api.updateMe({ current_password: cur, new_password: pw1 });
      setCur(""); setPw1(""); setPw2("");
      setMsg("Senha alterada.");
    } catch (e) { setErr(e.message); } finally { setBusy(false); }
  }

  return (
    <div className="modalOverlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modalHead">
          <h2 style={{ margin: 0 }}>Meu perfil</h2>
          <button className="btn" onClick={onClose}>✕</button>
        </div>

        <h3>Dados pessoais</h3>
        <label className="muted" style={{ fontSize: 12 }}>Nome</label>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Seu nome" />
        <label className="muted" style={{ fontSize: 12, marginTop: 8 }}>E-mail (login)</label>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <div className="row" style={{ marginTop: 10 }}>
          <button className="btn primary" disabled={busy} onClick={saveInfo}>Salvar dados</button>
        </div>

        <h3 style={{ marginTop: 18 }}>Alterar senha</h3>
        <label className="muted" style={{ fontSize: 12 }}>Senha atual</label>
        <input type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" />
        <div className="row" style={{ gap: 8, marginTop: 8 }}>
          <div style={{ flex: 1 }}>
            <label className="muted" style={{ fontSize: 12 }}>Nova senha</label>
            <input type="password" value={pw1} onChange={(e) => setPw1(e.target.value)} autoComplete="new-password" />
          </div>
          <div style={{ flex: 1 }}>
            <label className="muted" style={{ fontSize: 12 }}>Confirmar</label>
            <input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" />
          </div>
        </div>
        <div className="row" style={{ marginTop: 10 }}>
          <button className="btn primary" disabled={busy || !cur || !pw1} onClick={savePassword}>Alterar senha</button>
        </div>

        {msg && <div className="info" style={{ marginTop: 10 }}>{msg}</div>}
        {err && <div className="err" style={{ marginTop: 10 }}>{err}</div>}
      </div>
    </div>
  );
}
