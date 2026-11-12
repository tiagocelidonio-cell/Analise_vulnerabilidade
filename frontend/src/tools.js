// Catálogo de ferramentas (usado no catálogo "Nova varredura" e nos Ativos).
// kind define a máscara do alvo no formulário:
//   domain -> ex: cliente.com.br
//   url    -> ex: https://cliente.com.br  (http/https obrigatório)
//   host   -> ex: 10.0.0.0/24, 1.2.3.4 ou host  (IP, range ou hostname)
export const CATEGORIES = [
  {
    cat: "Recon", items: [
      { name: "Subdomain Finder", icon: "🌐", kind: "domain", desc: "subfinder + amass: subdomínios e hosts vivos de um domínio.", collectors: ["subdomain_enum"] },
      { name: "Website Recon", icon: "🔎", kind: "url", desc: "Fingerprint do site: servidor, TLS, security headers.", collectors: ["http_probe"] },
      { name: "Google Dorks", icon: "🧭", kind: "domain", desc: "Gera dorks prontos para exposições (arquivos, logins…).", collectors: ["google_dorks"] },
      { name: "Wayback", icon: "🕰️", kind: "domain", desc: "Arquivos sensíveis históricos (.env, .sql, backups…).", collectors: ["wayback"] },
    ],
  },
  {
    cat: "Varredura", items: [
      { name: "Port Scanner", icon: "📡", kind: "host", desc: "nmap: portas, serviços e versões. Completo = CVEs (script vulners).", collectors: ["port_scan"] },
      { name: "Network Scanner", icon: "🖧", kind: "host", desc: "nmap no range + serviços web. Acha todos os hosts ativos.", collectors: ["port_scan", "http_probe"] },
      { name: "Website Scanner", icon: "🕷️", kind: "url", desc: "Conteúdo exposto + nuclei (vulnerabilidades/CVEs).", collectors: ["http_probe", "web_content", "web_vuln"] },
    ],
  },
  {
    cat: "Automação / OT / IoT", items: [
      { name: "OT/IoT Detector", icon: "🏭", kind: "host", desc: "Protocolos industriais (Modbus, S7, MQTT…). Detecção passiva.", collectors: ["port_scan"] },
    ],
  },
  {
    cat: "Vulnerabilidades", items: [
      { name: "Vulnerability Scanner", icon: "🎯", kind: "url", desc: "nuclei: milhares de templates (CVEs, misconfig, exposições).", collectors: ["web_vuln"] },
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
