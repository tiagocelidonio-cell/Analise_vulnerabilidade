import React, { useState, useEffect } from "react";
import { api } from "./api.js";

// Portas do modo "Rápido". "Completo" usa top-200 do nmap (ports vazio).
const LIGHT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389,
  5432, 8080, 8443, 502, 102, 1883];

// Máscara = EXEMPLO (placeholder). Nunca pré-preenche com o escopo do cliente.
const MASKS = {
  domain: {
    placeholder: "ex.: cliente.com.br",
    hint: "Domínio, sem http:// — ex.: cliente.com.br",
  },
  url: {
    placeholder: "ex.: https://app.cliente.com.br",
    hint: "Site COM http:// ou https:// — ex.: https://app.cliente.com.br",
  },
  host: {
    placeholder: "ex.: 10.0.0.0/24   ou   192.168.1.44",
    hint: "IP, range/CIDR (ex.: 10.0.0.0/24) ou hostname. Acha hosts ativos sem ping.",
  },
};

function modeText(tool, scanType) {
  const c = tool.collectors || [];
  const port = c.includes("port_scan");
  const vuln = c.includes("web_vuln");
  if (scanType === "light") {
    const p = [];
    if (port) p.push("18 portas mais comuns");
    if (vuln) p.push("verificações de severidade alta/crítica");
    return "Básico: " + (p.join(" + ") || "varredura rápida") + ". Mais rápido, ideal para triagem.";
  }
  const p = [];
  if (port) p.push("top-200 portas com detecção de versão");
  if (vuln) p.push("todas as severidades");
  return "Completo: " + (p.join(" + ") || "varredura ampla") + ". Mais lento, mais cobertura.";
}

export default function ToolForm({ engagement, tool, onClose, onRan, onUpdated, initialTarget }) {
  const isExploit = tool.exploit !== undefined;
  const isPortTool = (tool.collectors || []).includes("port_scan");
  const hasCred = (tool.collectors || []).includes("cred_attack");
  const hasProfiles = (tool.collectors || []).some((c) => c === "port_scan" || c === "web_vuln");
  const mask = MASKS[tool.kind] || MASKS.host;

  // Ataque de credenciais: biblioteca + modo + colar na hora.
  const [wordlists, setWordlists] = useState([]);
  const [credLists, setCredLists] = useState(() => new Set());
  const [credMode, setCredMode] = useState("cauteloso");
  const [credExtra, setCredExtra] = useState("");
  useEffect(() => {
    if (!hasCred) return;
    api.listWordlists().then((ls) => {
      setWordlists(ls);
      // Por padrão marca as listas públicas embutidas.
      setCredLists(new Set(ls.filter((l) => l.builtin).map((l) => l.id)));
    }).catch(() => setWordlists([]));
  }, [hasCred]);
  function toggleCredList(id) {
    setCredLists((prev) => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }

  // Alvo começa VAZIO (máscara é só exemplo). Só herda se veio de "escanear
  // selecionados" nos Achados.
  const [target, setTarget] = useState(initialTarget || "");
  const [scanType, setScanType] = useState("light");
  const [customPorts, setCustomPorts] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [outOfScope, setOutOfScope] = useState(null);

  // Validação (item 8): alvos candidatos vêm dos serviços web já descobertos.
  const [candidates, setCandidates] = useState(null); // null = carregando
  const [picked, setPicked] = useState(() => new Set());

  // Sub-passos ("o que será executado"): catálogo + seleção (checkbox).
  const [stepMeta, setStepMeta] = useState(null);
  const [selSteps, setSelSteps] = useState(() => new Set());
  const collectorsKey = (tool.collectors || []).join(",");

  useEffect(() => {
    if (isExploit) return;
    (async () => {
      try {
        const meta = await api.scanSteps();
        setStepMeta(meta);
        const def = new Set();
        for (const c of tool.collectors || [])
          for (const s of meta[c] || [])
            if (s.default !== false) def.add(s.key);
        setSelSteps(def);
      } catch { setStepMeta({}); }
    })();
  }, [isExploit, collectorsKey]);

  const toolSteps = () =>
    (tool.collectors || []).flatMap((c) => (stepMeta && stepMeta[c]) || []);
  function toggleStep(key) {
    setSelSteps((prev) => {
      const n = new Set(prev);
      n.has(key) ? n.delete(key) : n.add(key);
      return n;
    });
  }

  useEffect(() => {
    if (!isExploit) return;
    (async () => {
      try {
        const fs = await api.listFindings(engagement.id);
        const webs = new Set();
        for (const f of fs) {
          const svc = (f.service || "").toLowerCase();
          if (svc === "http" || svc === "https" || [80, 443, 8080, 8443].includes(f.port)) {
            if (f.target) webs.add(f.target);
          }
        }
        const list = [...webs].sort();
        setCandidates(list);
        setPicked(new Set(list)); // começa com todos marcados
      } catch {
        setCandidates([]);
      }
    })();
  }, [isExploit, engagement.id]);

  const targetList = () => target.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

  function portsForRun() {
    if (!isPortTool) return [];
    if (customPorts.trim()) {
      return customPorts.split(/[\s,]+/).map((p) => parseInt(p, 10)).filter((n) => !isNaN(n));
    }
    return scanType === "light" ? LIGHT_PORTS : [];
  }

  function togglePick(h) {
    setPicked((prev) => {
      const n = new Set(prev);
      n.has(h) ? n.delete(h) : n.add(h);
      return n;
    });
  }

  async function start(addToScope = false) {
    setErr(""); setOutOfScope(null); setBusy(true);
    try {
      if (isExploit) {
        const chosen = [...picked];
        if (!chosen.length) {
          setErr("Selecione pelo menos um ativo para validar.");
          setBusy(false);
          return;
        }
        await api.validate(engagement.id, { intrusive: tool.exploit, targets: chosen });
        onRan && onRan(`${tool.name} iniciada — acompanhe em Achados › Scans em andamento.`);
        onClose();
        return;
      }
      if (addToScope) {
        const novo = [...new Set([...(engagement.scope || []), ...targetList()])];
        const upd = await api.updateEngagement(engagement.id, { scope: novo });
        onUpdated && onUpdated(upd);
      }
      await api.createScan(engagement.id, {
        targets: targetList(), ports: portsForRun(), collectors: tool.collectors,
        profile: scanType === "light" ? "basic" : "full",
        steps: [...selSteps],
        params: hasCred ? {
          cred_lists: [...credLists], cred_mode: credMode, cred_extra: credExtra,
        } : {},
      });
      onRan && onRan(`${tool.name} iniciada.`);
      onClose();
    } catch (e) {
      if (/fora do escopo/i.test(e.message)) {
        setOutOfScope(e.message);
      } else {
        setErr(e.message);
      }
    } finally { setBusy(false); }
  }

  // Item 8: o que a validação faz (checklist) por tipo.
  const validationActions = tool.exploit
    ? [
        "Prova de SQL injection (payloads de leitura, não-destrutivos)",
        "Prova de XSS refletido (injeção inofensiva, sem persistência)",
        "Prova de LFI / path traversal (leitura de arquivo de teste)",
        "Revalidação de exposições já sinalizadas",
      ]
    : [
        "Confirma, sem explorar, as falhas já encontradas",
        "Revalida cabeçalhos de segurança e TLS dos serviços web",
        "Repete requisições de leitura (GET) para registrar evidência",
      ];

  return (
    <div className="modalOverlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modalHead">
          <h2 style={{ margin: 0 }}>{tool.icon} {tool.name}</h2>
          <button className="btn" onClick={onClose}>✕</button>
        </div>
        <p className="muted">{tool.desc}</p>

        {isExploit ? (
          /* ---- Validação (SAFE / avançada) — item 8 ---- */
          <>
            <div className={tool.exploit ? "warn" : "info"}>
              <b>O que será feito</b> {tool.exploit
                ? "— validação avançada, intrusiva porém NÃO-destrutiva (opt-in do cliente):"
                : "— validação segura, apenas confirmação não-intrusiva:"}
              <ul className="checklist">
                {validationActions.map((a) => (
                  <li key={a}><span className="ck">☑</span> {a}</li>
                ))}
              </ul>
              <span style={{ fontSize: 12 }}>Sem ataques de disponibilidade (DoS), sem alterar dados.</span>
            </div>

            <label className="muted" style={{ fontSize: 12, marginTop: 10, display: "block" }}>
              Selecione os ativos a validar (não precisa ser todos):
            </label>
            {candidates === null ? (
              <div className="muted">Carregando ativos…</div>
            ) : candidates.length === 0 ? (
              <div className="err" style={{ marginTop: 6 }}>
                Nenhum serviço web descoberto ainda. Rode um <b>Website Scanner</b> ou
                <b> Port Scanner</b> antes de validar.
              </div>
            ) : (
              <>
                <div className="row" style={{ gap: 10, margin: "6px 0" }}>
                  <button className="btn" style={{ padding: "2px 8px" }}
                    onClick={() => setPicked(new Set(candidates))}>Todos</button>
                  <button className="btn" style={{ padding: "2px 8px" }}
                    onClick={() => setPicked(new Set())}>Nenhum</button>
                  <span className="muted" style={{ fontSize: 12 }}>{picked.size}/{candidates.length} selecionado(s)</span>
                </div>
                <div className="pickbox">
                  {candidates.map((h) => (
                    <label key={h} className="check" style={{ display: "flex" }}>
                      <input type="checkbox" checked={picked.has(h)} onChange={() => togglePick(h)} /> {h}
                    </label>
                  ))}
                </div>
              </>
            )}
          </>
        ) : (
          /* ---- Ferramentas de varredura/recon ---- */
          <>
            <label className="muted" style={{ fontSize: 12 }}>Alvo(s)</label>
            <input autoFocus value={target} onChange={(e) => setTarget(e.target.value)}
              placeholder={mask.placeholder} />
            <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>{mask.hint}</div>

            {hasProfiles ? (
              <>
                <div className="row" style={{ gap: 18, marginTop: 12 }}>
                  <span className="muted" style={{ fontSize: 13 }}>Profundidade:</span>
                  <label className="check"><input type="radio" checked={scanType === "light"}
                    onChange={() => setScanType("light")} /> Básico</label>
                  <label className="check"><input type="radio" checked={scanType === "full"}
                    onChange={() => setScanType("full")} /> Completo</label>
                </div>
                <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>{modeText(tool, scanType)}</div>
                {isPortTool && (
                  <div style={{ marginTop: 10 }}>
                    <label className="muted" style={{ fontSize: 12 }}>Portas específicas (opcional — vazio usa o padrão acima)</label>
                    <input value={customPorts} onChange={(e) => setCustomPorts(e.target.value)}
                      placeholder="ex.: 80, 443, 8080, 502" />
                  </div>
                )}
              </>
            ) : null}

            {/* O QUE SERÁ EXECUTADO — checklist de sub-passos (transparência). */}
            {stepMeta && toolSteps().length > 0 && (
              <div className="info" style={{ marginTop: 12 }}>
                <b>O que será executado</b> — desmarque o que não quiser rodar:
                <ul className="checklist" style={{ marginTop: 6, listStyle: "none", paddingLeft: 0 }}>
                  {toolSteps().map((s) => (
                    <li key={s.key} style={{ display: "flex", alignItems: "flex-start", gap: 7, margin: "5px 0" }}>
                      <input type="checkbox" checked={selSteps.has(s.key)}
                        disabled={s.togglable === false}
                        onChange={() => toggleStep(s.key)} style={{ marginTop: 3 }} />
                      <span>
                        {s.label}
                        {s.togglable === false &&
                          <span className="muted" style={{ fontSize: 11 }}> · sempre</span>}
                        {s.desc && <div className="muted" style={{ fontSize: 11 }}>{s.desc}</div>}
                      </span>
                    </li>
                  ))}
                </ul>
                <span className="muted" style={{ fontSize: 11 }}>
                  Passos marcados “sempre” são o núcleo da capacidade e não podem ser desligados.
                </span>
              </div>
            )}

            {/* ATAQUE DE CREDENCIAIS: biblioteca + modo + colar/importar. */}
            {hasCred && (
              <div className="info" style={{ marginTop: 12 }}>
                <b>Credenciais a testar</b>
                <div className="muted" style={{ fontSize: 11, marginBottom: 6 }}>
                  Escolha as listas da biblioteca (gerencie em Administração ›
                  Credenciais), cole credenciais na hora, ou ambos.
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4, maxHeight: 150, overflow: "auto" }}>
                  {wordlists.length === 0 && <span className="muted" style={{ fontSize: 12 }}>Nenhuma lista. Cole abaixo ou crie em Administração › Credenciais.</span>}
                  {wordlists.map((l) => (
                    <label key={l.id} className="check" style={{ display: "flex", gap: 6 }}>
                      <input type="checkbox" checked={credLists.has(l.id)} onChange={() => toggleCredList(l.id)} />
                      <span>{l.name} <span className="muted" style={{ fontSize: 11 }}>· {l.kind} · {l.count}{l.builtin ? " · público" : ""}</span></span>
                    </label>
                  ))}
                </div>

                <label className="muted" style={{ fontSize: 12, marginTop: 8, display: "block" }}>
                  Colar na hora (uma por linha — senha, ou user:pass):
                </label>
                <textarea value={credExtra} onChange={(e) => setCredExtra(e.target.value)}
                  placeholder={"admin:admin\nP@ssw0rd\nroot:toor"} style={{ minHeight: 60, fontFamily: "monospace", fontSize: 12 }} />
                <label className="btn" style={{ cursor: "pointer", marginTop: 4, display: "inline-block", padding: "3px 10px" }}>
                  Importar .txt
                  <input type="file" accept=".txt,text/plain" style={{ display: "none" }}
                    onChange={(e) => { const f = e.target.files?.[0]; if (!f) return;
                      const rd = new FileReader(); rd.onload = () => setCredExtra((p) => (p ? p + "\n" : "") + String(rd.result || "")); rd.readAsText(f); }} />
                </label>

                <label className="muted" style={{ fontSize: 12, marginTop: 10, display: "block" }}>Modo (velocidade × risco de bloqueio):</label>
                <div className="row" style={{ gap: 14, flexWrap: "wrap" }}>
                  {[["cauteloso", "Cauteloso (anti-lockout, seguro)"], ["balanceado", "Balanceado"], ["agressivo", "Agressivo (rápido — risco de bloqueio)"]].map(([v, l]) => (
                    <label key={v} className="check"><input type="radio" checked={credMode === v} onChange={() => setCredMode(v)} /> {l}</label>
                  ))}
                </div>
                {credMode === "agressivo" && (
                  <div className="warn" style={{ fontSize: 11, marginTop: 6 }}>
                    ⚠ Modo agressivo pode BLOQUEAR contas (lockout) em login web. Use só onde há autorização para isso (ex.: SSH/FTP). A estimativa de tempo aparece no log do scan.
                  </div>
                )}
              </div>
            )}
          </>
        )}

        {err && <div className="err" style={{ marginTop: 10 }}>{err}</div>}
        {outOfScope && (
          <div className="err" style={{ marginTop: 10 }}>
            {outOfScope}
            <div style={{ marginTop: 8 }}>
              <button className="btn primary" disabled={busy} onClick={() => start(true)}>
                Adicionar ao escopo e escanear
              </button>
            </div>
          </div>
        )}

        <div className="modalFoot">
          <button className="btn" onClick={onClose}>Cancelar</button>
          <button className="btn primary" disabled={busy} onClick={() => start(false)}>
            {busy ? "Iniciando…" : (isExploit ? "▶ Executar validação" : "▶ Iniciar scan")}
          </button>
        </div>
      </div>
    </div>
  );
}
