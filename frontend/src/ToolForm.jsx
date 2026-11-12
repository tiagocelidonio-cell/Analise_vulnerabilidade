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
    if (vuln) p.push("templates de severidade alta/crítica");
    return "Básico: " + (p.join(" + ") || "varredura rápida") + ". Mais rápido, ideal para triagem.";
  }
  const p = [];
  if (port) p.push("top-200 portas com versão (nmap -sV)");
  if (vuln) p.push("todas as severidades (nuclei)");
  return "Completo: " + (p.join(" + ") || "varredura ampla") + ". Mais lento, mais cobertura.";
}

export default function ToolForm({ engagement, tool, onClose, onRan, onUpdated, initialTarget }) {
  const isExploit = tool.exploit !== undefined;
  const isPortTool = (tool.collectors || []).includes("port_scan");
  const hasProfiles = (tool.collectors || []).some((c) => c === "port_scan" || c === "web_vuln");
  const mask = MASKS[tool.kind] || MASKS.host;

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
        const r = await api.validate(engagement.id, { intrusive: tool.exploit, targets: chosen });
        onRan && onRan(`${tool.name}: ${r.confirmed} confirmada(s) em ${r.tested_targets} alvo(s).`);
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
            ) : (
              <div className="info" style={{ marginTop: 12 }}>
                <b>Modo único.</b> Esta ferramenta roda sempre a mesma varredura
                padronizada — sem configuração extra.
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
