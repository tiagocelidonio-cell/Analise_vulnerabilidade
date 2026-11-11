import React, { useState } from "react";
import { api } from "./api.js";

export default function Login({ onLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setErr(""); setBusy(true);
    try {
      await api.login(email, password);
      const user = await api.me();
      onLogin(user);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  return (
    <div className="loginWrap">
      <form className="loginCard" onSubmit={submit}>
        <div className="brand" style={{ fontSize: 26, textAlign: "center" }}>VulnScope</div>
        <p className="muted" style={{ textAlign: "center", marginTop: 0 }}>
          Acesso restrito — faça login
        </p>
        <input type="email" placeholder="E-mail" value={email} autoFocus
          onChange={(e) => setEmail(e.target.value)} required />
        <input type="password" placeholder="Senha" value={password}
          onChange={(e) => setPassword(e.target.value)} required />
        {err && <div className="err">{err}</div>}
        <button className="btn primary block" type="submit" disabled={busy}>
          {busy ? "Entrando…" : "Entrar"}
        </button>
        <p className="muted" style={{ fontSize: 11, textAlign: "center" }}>
          Padrão inicial: admin@vulnscope.local / changeme — altere após o 1º acesso.
        </p>
      </form>
    </div>
  );
}
