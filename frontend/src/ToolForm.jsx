import React, { useState } from "react";
import { api } from "./api.js";

// Portas do modo "Rápido". "Completo" usa top-200 do nmap (ports vazio).
const LIGHT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389,
  5432, 8080, 8443, 502, 102, 1883];

// Máscara/ajuda por tipo de alvo (tool.kind).
const MASKS = {
  domain: {
    placeholder: "cliente.com.br",
    hint: "Informe o domínio (sem http://). Ex.: cliente.com.br",
  },
  url: {
    placeholder: "https://cliente.com.br",
    hint: "Informe o site COM http:// ou https://. Ex.: https://app.cliente.com.br",
  },
  host: {
    placeholder: "10.0.0.0/24   ou   192.168.1.44   ou   host.cliente.com.br",
    hint: "IP, range/CIDR (ex.: 10.0.0.0/24) ou hostname. Encontra hosts ativos mesmo sem ping.",
  },
};

export default function ToolForm({ engagement, tool, onClose, onRan, onUpdated, initialTarget }) {
  const isExploit = tool.exploit !== undefined;
  const isPortTool = (tool.collectors || []).includes("port_scan");
  const mask = MASKS[tool.kind] || MASKS.host;

  const [target, setTarget] = useState(initialTarget || (engagement.scope || []).join(" "));
  const [scanType, setScanType] = useState("light");
  const [customPorts, setCustomPorts] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [outOfScope, setOutOfScope] = useState(null);

  const targetList = () => target.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

  function portsForRun() {
    if (!isPortTool) return [];
    if (customPorts.trim()) {
      return customPorts.split(/[\s,]+/).map((p) => parseInt(p, 10)).filter((n) => !isNaN(n));
    }
    return scanType === "light" ? LIGHT_PORTS : [];
  }

  async function start(addToScope = false) {
    setErr(""); setOutOfScope(null); setBusy(true);
    try {
      if (addToScope) {
        const novo = [...new Set([...(engagement.scope || []), ...targetList()])];
        const upd = await api.updateEngagement(engagement.id, { scope: novo });
        onUpdated && onUpdated(upd);
      }
      if (isExploit) {
        const r = await api.validate(engagement.id, tool.exploit);
        onRan && onRan(`${tool.name}: ${r.confirmed} confirmada(s) em ${r.tested_targets} alvo(s).`);
      } else {
        await api.createScan(engagement.id, {
          targets: targetList(), ports: portsForRun(), collectors: tool.collectors,
        });
        onRan && onRan(`${tool.name} iniciada.`);
      }
      onClose();
    } catch (e) {
      // Alvo fora do escopo -> oferece cadastrar o ativo no escopo.
      if (/fora do escopo/i.test(e.message)) {
        setOutOfScope(e.message);
      } else {
        setErr(e.message);
      }
    } finally { setBusy(false); }
  }

  // Item 8: a "validação" deixa claro O QUE faz e QUAIS ativos analisa.
  const validationActions = tool.exploit
    ? [
        "Prova de SQL injection (payloads de leitura, não-destrutivos)",
        "Prova de XSS refletido (injeção inofensiva, sem persistência)",
        "Prova de LFI / path traversal (leitura de arquivo de teste)",
        "Checagem de cabeçalhos e exposições já sinalizadas",
      ]
    : [
        "Confirma, sem explorar, as falhas já encontradas",
        "Revalida cabeçalhos de segurança e TLS dos serviços web",
        "Repete requisições de leitura (GET) para evidência",
      ];

  return (
    <div className="modalOverlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modalHead">
          <h2 style={{ margin: 0 }}>{tool.icon} {tool.name}</h2>
          <button className="btn" onClick={onClose}>✕</button>
        </div>
        <p className="muted">{tool.desc}</p>

        {tool.exploit !== undefined ? (
          /* ---- Validação (SAFE / avançada) — item 8 ---- */
          <>
            <div className={tool.exploit ? "warn" : "info"}>
              <b>O que será feito</b> {tool.exploit
                ? "— validação avançada, intrusiva porém NÃO-destrutiva (requer opt-in do cliente):"
                : "— validação segura, apenas confirmação não-intrusiva:"}
              <ul className="checklist">
                {validationActions.map((a) => (
                  <li key={a}><span className="ck">☑</span> {a}</li>
                ))}
              </ul>
            </div>
            <div className="info" style={{ marginTop: 8 }}>
              <b>Quais ativos</b> — somente os <b>serviços web já descobertos</b> nas
              fases anteriores (não varre todo o escopo). Sem ataques de
              disponibilidade (DoS), sem alteração de dados.
            </div>
          </>
        ) : (
          /* ---- Ferramentas de varredura/recon ---- */
          <>
            <label className="muted" style={{ fontSize: 12 }}>Alvo(s)</label>
            <input autoFocus value={target} onChange={(e) => setTarget(e.target.value)}
              placeholder={mask.placeholder} />
            <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>{mask.hint}</div>

            {isPortTool ? (
              <>
                <div className="row" style={{ gap: 18, marginTop: 12 }}>
                  <span className="muted" style={{ fontSize: 13 }}>Profundidade:</span>
                  <label className="check"><input type="radio" checked={scanType === "light"}
                    onChange={() => setScanType("light")} /> Rápido</label>
                  <label className="check"><input type="radio" checked={scanType === "full"}
                    onChange={() => setScanType("full")} /> Completo</label>
                </div>
                <div className="muted" style={{ fontSize: 11, marginTop: 4 }}>
                  {scanType === "light"
                    ? "Básico: 18 portas mais comuns (rápido, bom para triagem)."
                    : "Completo: top-200 portas com detecção de versão (nmap -sV). Mais lento, mais cobertura."}
                </div>
                <div style={{ marginTop: 10 }}>
                  <label className="muted" style={{ fontSize: 12 }}>Portas específicas (opcional — vazio usa o padrão acima)</label>
                  <input value={customPorts} onChange={(e) => setCustomPorts(e.target.value)}
                    placeholder="ex: 80, 443, 8080, 502" />
                </div>
              </>
            ) : (
              <div className="info" style={{ marginTop: 12 }}>
                <b>Como funciona:</b> {tool.desc} Scan único e padronizado — sem
                configuração extra necessária.
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
            {busy ? "Iniciando…" : (tool.exploit !== undefined ? "▶ Executar validação" : "▶ Iniciar scan")}
          </button>
        </div>
      </div>
    </div>
  );
}
