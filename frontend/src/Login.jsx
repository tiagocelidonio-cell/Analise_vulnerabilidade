import React, { useEffect, useState } from "react";
import { api } from "./api.js";
import { branding } from "./branding.js";

export default function Login({ onLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [firstRun, setFirstRun] = useState(false);

  // Só mostra o aviso de credencial padrão no PRIMEIRO acesso do sistema.
  useEffect(() => {
    let on = true;
    api.getConfig().then((c) => { if (on) setFirstRun(!!c.first_run); })
      .catch(() => {});
    return () => { on = false; };
  }, []);

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

  const name = (branding.appName || "").trim();
  const showName = name.length > 1;

  return (
    <div className="loginWrap">
      <form className="loginCard" onSubmit={submit}>
        <img src={branding.logo} alt={name || "logo"} className="loginLogo" />
        {showName && <div className="loginName">{name}</div>}
        <p className="muted" style={{ textAlign: "center", margin: "2px 0 14px" }}>
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
        {firstRun && (
          <p className="muted" style={{ fontSize: 11, textAlign: "center", marginBottom: 0 }}>
            Padrão inicial: admin@vulnscope.local / changeme — altere após o 1º acesso.
          </p>
        )}
      </form>
    </div>
  );
}
