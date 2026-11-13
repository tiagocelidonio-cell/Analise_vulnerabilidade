// Catálogo de ferramentas (usado no catálogo "Nova varredura" e nos Ativos).
// kind define a máscara do alvo no formulário:
//   domain -> ex: cliente.com.br
//   url    -> ex: https://cliente.com.br  (http/https obrigatório)
//   host   -> ex: 10.0.0.0/24, 1.2.3.4 ou host  (IP, range ou hostname)
export const CATEGORIES = [
  {
    cat: "Recon", items: [
      { name: "Subdomain Finder", icon: "🌐", kind: "domain", desc: "subfinder + amass: subdomínios e hosts vivos de um domínio.", collectors: ["subdomain_enum"] },
      { name: "OSINT", icon: "🕵️", kind: "domain", desc: "Pegada pública: e-mails, domínios (crt.sh) e IPs da empresa.", collectors: ["osint"] },
      { name: "Website Recon", icon: "🔎", kind: "url", desc: "Fingerprint do site: servidor, TLS, security headers.", collectors: ["http_probe", "tech_detect"] },
      { name: "Google Dorks", icon: "🧭", kind: "domain", desc: "Busca exposições via Google (API oficial, se configurada); senão gera o checklist.", collectors: ["google_dorks"] },
      { name: "Wayback", icon: "🕰️", kind: "domain", desc: "Arquivos sensíveis históricos (.env, .sql, backups…).", collectors: ["wayback"] },
      { name: "Vazamentos", icon: "💧", kind: "domain", desc: "E-mails/domínios em vazamentos conhecidos (HIBP). Requer chave.", collectors: ["leaks"] },
    ],
  },
  {
    cat: "Varredura", items: [
      { name: "Port Scanner", icon: "📡", kind: "host", desc: "nmap: portas, serviços e versões. Completo = CVEs (script vulners).", collectors: ["port_scan"] },
      { name: "Network Scanner", icon: "🖧", kind: "host", desc: "nmap no range + tecnologias + screenshot. Acha todos os hosts ativos.", collectors: ["port_scan", "http_probe", "tech_detect", "screenshot"] },
      { name: "Website Scanner", icon: "🕷️", kind: "url", desc: "Conteúdo + tecnologias + screenshot + nuclei (vulnerabilidades/CVEs).", collectors: ["http_probe", "web_content", "tech_detect", "screenshot", "web_vuln"] },
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
