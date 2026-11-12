// Catálogo de ferramentas (usado no catálogo "Nova varredura" e nos Ativos).
export const CATEGORIES = [
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
      { name: "Port Scanner", icon: "📡", desc: "nmap: portas, serviços e versões (acha host sem ping).", collectors: ["port_scan"] },
      { name: "Network Scanner", icon: "🖧", desc: "nmap no range + serviços web. Acha todos os hosts ativos.", collectors: ["port_scan", "http_probe"] },
      { name: "Website Scanner", icon: "🕷️", desc: "Conteúdo exposto + nuclei (vulnerabilidades/CVEs).", collectors: ["http_probe", "web_content", "web_vuln"] },
    ],
  },
  {
    cat: "Vulnerabilidades", items: [
      { name: "Vulnerability Scanner", icon: "🎯", desc: "nuclei: milhares de templates (CVEs, misconfig, exposições).", collectors: ["web_vuln"] },
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

export const FLAT_TOOLS = CATEGORIES.flatMap((c) => c.items);
