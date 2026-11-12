import React, { useEffect, useState, useCallback } from "react";
import { api } from "./api.js";

const RECON = ["subdomain_enum", "wayback", "google_dorks"];
const SCAN = ["port_scan", "http_probe", "web_content"];

function Badge({ status }) {
  const map = {
    pendente: { t: "pendente", c: "#334155" },
    rodando: { t: "em andamento", c: "#a16207" },
    concluido: { t: "concluído", c: "#15803d" },
  };
  const s = map[status] || map.pendente;
  return <span className="pill" style={{ background: s.c }}>{s.t}</span>;
}

function Phase({ n, title, desc, status, children }) {
  return (
    <div className="phase">
      <div className="phaseHead">
        <div className="phaseNum">{n}</div>
        <div style={{ flex: 1 }}>
          <div className="phaseTitle">{title}</div>
          <div className="muted" style={{ fontSize: 12 }}>{desc}</div>
        </div>
        <Badge status={status} />
      </div>
      <div className="phaseBody">{children}</div>
    </div>
  );
}

export default function Playbook({ engagement }) {
  const [targets, setTargets] = useState((engagement.scope || []).join(" "));
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [post, setPost] = useState(null);
  const [retest, setRetest] = useState(null);
  const [exploitLog, setExploitLog] = useState(null);
  const [exploitResult, setExploitResult] = useState(null);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState("");

  const refresh = useCallback(async () => {
    const [s, f] = await Promise.all([
      api.listScans(engagement.id), api.listFindings(engagement.id),
    ]);
    setScans(s); setFindings(f);
  }, [engagement.id]);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    if (!scans.some((s) => ["queued", "running"].includes(s.status))) return;
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [scans, refresh]);

  const targetList = () => targets.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

  function phaseStatus(collectors) {
    const rel = scans.filter((s) =>
      (s.collectors.length ? s.collectors : SCAN).some((c) => collectors.includes(c)));
    if (rel.some((s) => ["queued", "running"].includes(s.status))) return "rodando";
    if (rel.some((s) => s.status === "completed")) return "concluido";
    return "pendente";
  }

  async function runScan(collectors, label) {
    setMsg(""); setBusy(label);
    try {
      await api.createScan(engagement.id, { targets: targetList(), ports: [], collectors });
      await refresh();
    } catch (e) { setMsg(e.message); }
    finally { setBusy(""); }
  }

  async function runValidate(intrusive) {
    if (intrusive && !window.confirm(
      "Validação INTRUSIVA (não-destrutiva). Confirme autorização por escrito do cliente."
    )) return;
    setMsg(""); setBusy("exploit");
    try {
      const r = await api.validate(engagement.id, intrusive);
      setExploitLog(r.log || []);
      setExploitResult(r);
      await refresh();
    } catch (e) { setMsg(e.message); }
    finally { setBusy(""); }
  }

  async function runPost() {
    setMsg(""); setBusy("post");
    try { setPost(await api.postexploit(engagement.id)); }
    catch (e) { setMsg(e.message); }
    finally { setBusy(""); }
  }

  async function runRetest() {
    setMsg(""); setBusy("retest");
    try {
      const r = await api.retest(engagement.id);
      setRetest(r);
      await refresh();
    } catch (e) { setMsg(e.message); }
    finally { setBusy(""); }
  }

  const reconStatus = phaseStatus(RECON);
  const scanStatus = phaseStatus(SCAN);
  const exploitDone = findings.some((f) => f.service === "exploit");
  const retestDone = findings.some((f) => (f.ai_assessment || {}).retest);
  const findingsN = findings.length;

  const BUSY_LABEL = {
    recon: "Reconhecimento", scan: "Varredura", exploit: "Exploração",
    post: "Pós-exploração", retest: "Reteste",
  };
  const runningScan = scans.find((s) => ["queued", "running"].includes(s.status));
  const activity = BUSY_LABEL[busy]
    || (runningScan ? `Varredura (${runningScan.progress || 0}% · ${runningScan.phase || "na fila"})` : null);
  const donePhases = [reconStatus === "concluido", scanStatus === "concluido",
    exploitDone, !!post, findingsN > 0, retestDone].filter(Boolean).length;

  return (
    <div>
      <div className="head">
        <div>
          <h2>Playbook</h2>
          <p className="muted">{donePhases} de 6 fases concluídas · {findingsN} achados</p>
        </div>
      </div>

      <div className="card">
        <label className="muted" style={{ fontSize: 12 }}>Alvos (domínios/IPs/hosts)</label>
        <input value={targets} onChange={(e) => setTargets(e.target.value)}
          placeholder="ex: cliente.com.br 10.0.0.0/24" />
        {!engagement.authorized && <div className="err">Engagement não autorizado — scans serão bloqueados.</div>}
        {msg && <div className="err">{msg}</div>}
      </div>

      {activity && (
        <div className="running"><span className="spin" /> Executando: {activity}…</div>
      )}

      <Phase n="1" title="Reconhecimento" status={reconStatus}
        desc="OSINT e subdomínios">
        <button className="btn primary" disabled={busy === "recon"}
          onClick={() => runScan(RECON, "recon")}>
          {busy === "recon" ? "Iniciando…" : "Executar"}
        </button>
      </Phase>

      <Phase n="2" title="Varredura e Enumeração" status={scanStatus}
        desc="Portas, serviços, web e automação/OT (IoT)">
        <button className="btn primary" disabled={busy === "scan"}
          onClick={() => runScan(SCAN, "scan")}>
          {busy === "scan" ? "Iniciando…" : "Executar"}
        </button>
      </Phase>

      <Phase n="3" title="Exploração" status={exploitDone ? "concluido" : "pendente"}
        desc="Prova as falhas, sem DoS">
        <div className="row">
          <button className="btn primary" disabled={busy === "exploit"}
            onClick={() => runValidate(false)}>
            {busy === "exploit" ? "Executando…" : "Exploração"}
          </button>
          {engagement.allow_intrusive && (
            <button className="btn danger" disabled={busy === "exploit"}
              onClick={() => runValidate(true)}>Exploração avançada</button>
          )}
        </div>
        {exploitResult && exploitResult.tested_targets === 0 && (
          <div className="info" style={{ marginTop: 8 }}>
            Nenhum alvo web para validar. Rode a <b>Varredura</b> (fase 2) primeiro —
            a exploração atua sobre os serviços web encontrados lá.
          </div>
        )}
        {exploitResult && exploitResult.tested_targets > 0 && (
          <p style={{ marginTop: 8 }}>
            <b>{exploitResult.confirmed}</b> falha(s) confirmada(s) em{" "}
            {exploitResult.tested_targets} alvo(s).
          </p>
        )}
        {exploitLog && exploitLog.length > 0 && (
          <div style={{ marginTop: 10 }}>
            <h3 style={{ fontSize: 13 }}>Evidências (o que foi executado)</h3>
            {exploitLog.map((e, i) => (
              <div key={i} className="probe">
                <div><span className="pill" style={{ background: e.tier === "intrusive" ? "#c2410c" : "#15803d" }}>
                  {e.tier.toUpperCase()}</span> <b style={{ marginLeft: 6 }}>{e.probe}</b> — {e.target}</div>
                <p style={{ margin: "6px 0" }}>{e.note}</p>
                {e.command && <pre className="cmd">$ {e.command}</pre>}
                {e.proof && <pre className="evi">{e.proof}</pre>}
              </div>
            ))}
          </div>
        )}
      </Phase>

      <Phase n="4" title="Pós-Exploração" status={post ? "concluido" : "pendente"}
        desc="Mapa de impacto e movimentação lateral (guiado)">
        <button className="btn primary" disabled={busy === "post"} onClick={runPost}>
          {busy === "post" ? "Analisando…" : "Gerar mapa de impacto"}
        </button>
        {post && (
          <div style={{ marginTop: 10 }}>
            <div className="row" style={{ gap: 18, flexWrap: "wrap" }}>
              <span>Confirmados: <b>{post.summary.confirmed}</b></span>
              <span>Segredos: <b>{post.summary.secrets}</b></span>
              <span>Alvos de alto valor: <b>{post.summary.high_value}</b></span>
              <span style={{ color: post.summary.ot ? "#b91c1c" : "inherit" }}>
                OT/IoT: <b>{post.summary.ot}</b></span>
            </div>
            <h3 style={{ marginTop: 10 }}>Checklist</h3>
            <ul className="checklist">
              {post.checklist.map((c, i) => <li key={i}>{c}</li>)}
            </ul>
          </div>
        )}
      </Phase>

      <Phase n="5" title="Relatório e Mitigação" status={findingsN ? "concluido" : "pendente"}
        desc="PDF executivo e técnico">
        <div className="row">
          <a className="btn" href={api.reportHtmlUrl(engagement.id)} target="_blank" rel="noreferrer">Preview</a>
          <a className="btn primary" href={api.reportPdfUrl(engagement.id)}>Baixar PDF</a>
        </div>
      </Phase>

      <Phase n="6" title="Reteste" status={retestDone ? "concluido" : "pendente"}
        desc="Confirma o que foi corrigido">
        <button className="btn primary" disabled={busy === "retest"} onClick={runRetest}>
          {busy === "retest" ? "Retestando…" : "Executar"}
        </button>
        {retest && (
          <p style={{ marginTop: 8 }}>
            ✅ Corrigidas: <b>{retest.corrigido}</b> &nbsp;·&nbsp;
            ❌ Ainda abertas: <b style={{ color: "#b91c1c" }}>{retest.aberto}</b>
            &nbsp;(de {retest.tested} confirmadas)
          </p>
        )}
      </Phase>
    </div>
  );
}
