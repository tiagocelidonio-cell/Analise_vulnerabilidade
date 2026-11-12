import React, { useState } from "react";
import ToolForm from "./ToolForm.jsx";

// Ferramentas nomeadas (cada uma mapeia para coletores/ação), por categoria.
const CATEGORIES = [
  {
    cat: "Recon", items: [
      { name: "Subdomain Finder", icon: "🌐", desc: "Descobre subdomínios e hosts vivos de um domínio.", collectors: ["subdomain_enum"] },
      { name: "Website Recon", icon: "🔎", desc: "Fingerprint do site: servidor, TLS, security headers.", collectors: ["http_probe"] },
      { name: "Google Dorks", icon: "🧭", desc: "Gera dorks prontos para exposições (arquivos, logins…).", collectors: ["google_dorks"] },
      { name: "Wayback", icon: "🕰️", desc: "Arquivos sensíveis históricos (.env, .sql, backups…).", collectors: ["wayback"] },
    ],
  },
  {
    cat: "Varredura", items: [
      { name: "Port Scanner", icon: "📡", desc: "Portas abertas e serviços (TCP connect, sem ping).", collectors: ["port_scan"] },
      { name: "Network Scanner", icon: "🖧", desc: "Varredura de rede/range + correlação CVE.", collectors: ["port_scan", "http_probe"] },
      { name: "Website Scanner", icon: "🕷️", desc: "Conteúdo web e arquivos expostos (/admin, /.git…).", collectors: ["http_probe", "web_content"] },
    ],
  },
  {
    cat: "Automação / OT / IoT", items: [
      { name: "OT/IoT Detector", icon: "🏭", desc: "Protocolos industriais (Modbus, S7, MQTT…). Detecção passiva.", collectors: ["port_scan"] },
    ],
  },
  {
    cat: "Exploração", items: [
      { name: "Validação (SAFE)", icon: "🛡️", desc: "Prova não-destrutiva das falhas encontradas.", exploit: false },
      { name: "Validação avançada", icon: "⚔️", desc: "SQLi/XSS/LFI (não-destrutivo). Requer opt-in.", exploit: true, needsIntrusive: true },
    ],
  },
];

export default function ToolCatalog({ engagement, onRan, onUpdated }) {
  const [openTool, setOpenTool] = useState(null);
  const [msg, setMsg] = useState("");

  return (
    <div>
      <div className="head"><div>
        <h2>Nova varredura</h2>
        <p className="muted">Escolha uma ferramenta, informe o alvo e inicie o scan.</p>
      </div></div>

      {msg && <div className="info">{msg}</div>}

      {CATEGORIES.map((c) => (
        <div key={c.cat} style={{ marginTop: 16 }}>
          <h3>{c.cat}</h3>
          <div className="toolGrid">
            {c.items.map((t) => {
              const locked = t.needsIntrusive && !engagement.allow_intrusive;
              return (
                <button key={t.name} className="toolCard" disabled={locked}
                  onClick={() => setOpenTool(t)}>
                  <div className="toolIcon">{t.icon}</div>
                  <div style={{ flex: 1 }}>
                    <div className="toolName">{t.name}</div>
                    <div className="muted" style={{ fontSize: 12 }}>{t.desc}</div>
                    {locked && (
                      <div style={{ fontSize: 11, color: "#a16207" }}>
                        ative "sondas intrusivas" no cliente
                      </div>
                    )}
                  </div>
                  <span className="muted" style={{ fontSize: 12 }}>Configurar ▸</span>
                </button>
              );
            })}
          </div>
        </div>
      ))}

      {openTool && (
        <ToolForm engagement={engagement} tool={openTool}
          onClose={() => setOpenTool(null)}
          onUpdated={onUpdated}
          onRan={(m) => { setMsg(m); onRan && onRan(); }} />
      )}
    </div>
  );
}
