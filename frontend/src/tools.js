// Catálogo de CAPACIDADES (nomes funcionais, neutros — sem expor a ferramenta).
// kind define a máscara do alvo no formulário:
//   domain -> ex: cliente.com.br
//   url    -> ex: https://cliente.com.br  (http/https obrigatório)
//   host   -> ex: 10.0.0.0/24, 1.2.3.4 ou host  (IP, range ou hostname)
export const CATEGORIES = [
  {
    cat: "Reconhecimento", items: [
      { name: "Enumeração de Ativos", icon: "🌐", kind: "domain", desc: "Descobre subdomínios e hosts vivos de um domínio.", collectors: ["subdomain_enum"] },
      { name: "OSINT", icon: "🕵️", kind: "domain", desc: "Pegada pública: e-mails, domínios e IPs da empresa.", collectors: ["osint"] },
      { name: "Reconhecimento Web", icon: "🔎", kind: "url", desc: "Fingerprint do site: servidor, TLS, cabeçalhos de segurança e tecnologias.", collectors: ["http_probe", "tech_detect"] },
      { name: "Busca por Exposições", icon: "🧭", kind: "domain", desc: "Localiza exposições públicas (arquivos, logins, vazamentos indexados).", collectors: ["google_dorks"] },
      { name: "Arquivos Históricos", icon: "🕰️", kind: "domain", desc: "Arquivos sensíveis já publicados (.env, .sql, backups…).", collectors: ["wayback"] },
      { name: "Vazamentos", icon: "💧", kind: "domain", desc: "E-mails/domínios em vazamentos conhecidos. Requer integração.", collectors: ["leaks"] },
    ],
  },
  {
    cat: "Varredura", items: [
      { name: "Descoberta de Portas", icon: "📡", kind: "host", desc: "Portas, serviços e versões (acha host sem ping). Completo = CVEs por versão.", collectors: ["port_scan"] },
      { name: "Varredura de Rede", icon: "🖧", kind: "host", desc: "Range completo + tecnologias + captura de tela. Acha todos os hosts ativos.", collectors: ["port_scan", "http_probe", "tech_detect", "screenshot"] },
      { name: "Varredura Web", icon: "🕷️", kind: "url", desc: "Conteúdo exposto + tecnologias + captura de tela + verificação de vulnerabilidades.", collectors: ["http_probe", "web_content", "tech_detect", "screenshot", "web_vuln"] },
    ],
  },
  {
    cat: "Automação / OT / IoT", items: [
      { name: "Detecção OT/IoT", icon: "🏭", kind: "host", desc: "Protocolos industriais (Modbus, S7, MQTT…). Detecção passiva.", collectors: ["port_scan"] },
    ],
  },
  {
    cat: "Vulnerabilidades", items: [
      { name: "Verificação de Vulnerabilidades", icon: "🎯", kind: "url", desc: "Milhares de verificações (CVEs, misconfig, exposições).", collectors: ["web_vuln"] },
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
