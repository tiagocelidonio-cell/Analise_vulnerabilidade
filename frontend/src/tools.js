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

export const FLAT_TOOLS = CATEGORIES.flatMap((c) => c.items);
