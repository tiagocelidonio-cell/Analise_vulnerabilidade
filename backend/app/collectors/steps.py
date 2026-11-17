"""Sub-passos (o que cada capacidade executa por dentro) — transparência + controle.

A UI mostra isto como um checklist por ferramenta ("o que será executado").
- togglable=True  -> o usuário liga/desliga de verdade (afeta a execução).
- togglable=False -> informativo (sempre roda; é o núcleo da capacidade).
Nomes SEMPRE funcionais (nunca o binário por trás). As chaves são globais no
formato "<collector>:<passo>" e são o contrato entre UI, API e worker.
"""
from __future__ import annotations

COLLECTOR_STEPS: dict[str, list[dict]] = {
    "subdomain_enum": [
        {"key": "subdomain_enum:source1", "togglable": False, "default": True,
         "label": "Fontes passivas (CT logs, DNS, APIs públicas)"},
        {"key": "subdomain_enum:source2", "togglable": True, "default": True,
         "label": "Segunda fonte de enumeração (passiva)",
         "desc": "Cruza outra fonte passiva para ampliar a cobertura. Mais lento."},
        {"key": "subdomain_enum:resolve", "togglable": True, "default": True,
         "label": "Resolver DNS (marcar quais estão vivos)",
         "desc": "Resolve cada subdomínio (registro A) e marca os que respondem."},
    ],
    "osint": [
        {"key": "osint:emails", "togglable": False, "default": True,
         "label": "Coleta de e-mails (site + busca pública)"},
        {"key": "osint:domains", "togglable": False, "default": True,
         "label": "Domínios relacionados (Certificate Transparency)"},
        {"key": "osint:ips", "togglable": False, "default": True,
         "label": "IPs/infra expostos"},
    ],
    "http_probe": [
        {"key": "http_probe:fingerprint", "togglable": False, "default": True,
         "label": "Fingerprint HTTP (servidor, título, status)"},
        {"key": "http_probe:security_headers", "togglable": True, "default": True,
         "label": "Cabeçalhos de segurança ausentes",
         "desc": "Checa CSP, X-Frame-Options, X-Content-Type-Options, HSTS…"},
        {"key": "http_probe:tls_cert", "togglable": True, "default": True,
         "label": "Validade do certificado TLS",
         "desc": "Alerta certificado expirado ou perto de vencer."},
    ],
    "tech_detect": [
        {"key": "tech_detect:fingerprint", "togglable": False, "default": True,
         "label": "Detecção de tecnologias (headers, cookies, HTML)"},
    ],
    "web_content": [
        {"key": "web_content:paths", "togglable": False, "default": True,
         "label": "Busca de caminhos/arquivos sensíveis expostos"},
    ],
    "web_vuln": [
        {"key": "web_vuln:templates", "togglable": False, "default": True,
         "label": "Verificações por template (CVEs, misconfig, exposições)"},
    ],
    "web_exploit": [
        {"key": "web_exploit:crawl", "togglable": False, "default": True,
         "label": "Rastreio da aplicação (descobre pontos de injeção)"},
        {"key": "web_exploit:xss", "togglable": True, "default": True,
         "label": "XSS refletido",
         "desc": "Injeta marcador único e confirma reflexão sem escape."},
        {"key": "web_exploit:sqli", "togglable": True, "default": True,
         "label": "SQL injection (erro + booleano)",
         "desc": "Não-destrutivo: só leitura lógica, nunca apaga/edita dados."},
    ],
    "port_scan": [
        {"key": "port_scan:ports", "togglable": False, "default": True,
         "label": "Portas e serviços abertos (acha host sem ping)"},
        {"key": "port_scan:version", "togglable": True, "default": True,
         "label": "Detecção de versão do serviço",
         "desc": "Identifica produto/versão (alimenta a correlação de CVE). Mais lento."},
        {"key": "port_scan:cve_local", "togglable": True, "default": True,
         "label": "CVE por versão (base local)",
         "desc": "Correlaciona a versão achada com CVEs localmente. Usa a detecção de versão."},
    ],
    "host_discovery": [
        {"key": "host_discovery:tcp", "togglable": False, "default": True,
         "label": "Sondagem TCP de hosts ativos (sem depender de ping)"},
    ],
    "screenshot": [
        {"key": "screenshot:capture", "togglable": False, "default": True,
         "label": "Captura de tela via navegador headless"},
    ],
    "wayback": [
        {"key": "wayback:archive", "togglable": False, "default": True,
         "label": "Consulta ao histórico de arquivos publicados (Wayback)"},
    ],
    "google_dorks": [
        {"key": "google_dorks:dorks", "togglable": False, "default": True,
         "label": "Consultas de exposição (dorks) via busca oficial"},
    ],
    "leaks": [
        {"key": "leaks:hibp", "togglable": False, "default": True,
         "label": "Checagem de vazamentos de credenciais conhecidos"},
    ],
}


def steps_for(collector: str) -> list[dict]:
    return COLLECTOR_STEPS.get(collector, [])


def default_selected(collectors) -> list[str]:
    """Chaves marcadas por padrão para os coletores de uma ferramenta."""
    out: list[str] = []
    for c in collectors or []:
        for s in COLLECTOR_STEPS.get(c, []):
            if s.get("default", True):
                out.append(s["key"])
    return out


def collector_enabled_steps(collector: str, selected: set | None) -> set | None:
    """Passos ATIVOS deste coletor. None = roda tudo (back-compat).

    Passos não-togglaveis entram sempre (são o núcleo). Se o coletor não
    declara passos, retorna None (nada a filtrar)."""
    decl = COLLECTOR_STEPS.get(collector, [])
    if not decl or selected is None:
        return None
    all_keys = {s["key"] for s in decl}
    fixed = {s["key"] for s in decl if not s.get("togglable", True)}
    return (all_keys & selected) | fixed
