from app.collectors.api_exploit import ApiExploitCollector
from app.collectors.content_discovery import ContentDiscoveryCollector
from app.collectors.cred_attack import CredAttackCollector
from app.collectors.google_dorks import GoogleDorksCollector
from app.collectors.host_discovery import HostDiscoveryCollector
from app.collectors.http_probe import HttpProbeCollector
from app.collectors.leaks import LeaksCollector
from app.collectors.nmap_scan import NmapCollector
from app.collectors.nuclei_scan import NucleiCollector
from app.collectors.osint import OsintCollector
from app.collectors.screenshot import ScreenshotCollector
from app.collectors.subfinder_scan import SubfinderCollector
from app.collectors.tech_detect import TechDetectCollector
from app.collectors.wayback import WaybackCollector
from app.collectors.web_content import WebContentCollector
from app.collectors.web_exploit import WebExploitCollector

# Registro de coletores disponiveis. Ferramentas consagradas com fallback Python:
#   port_scan     -> nmap   (fallback: scanner TCP proprio)
#   subdomain_enum-> subfinder (fallback: crt.sh + wordlist)
#   web_vuln      -> nuclei (sem fallback; vazio se ausente)
COLLECTORS = {
    "host_discovery": HostDiscoveryCollector(),
    "port_scan": NmapCollector(),
    "http_probe": HttpProbeCollector(),
    "web_content": WebContentCollector(),
    "content_discovery": ContentDiscoveryCollector(),
    "web_vuln": NucleiCollector(),
    "subdomain_enum": SubfinderCollector(),
    "wayback": WaybackCollector(),
    "google_dorks": GoogleDorksCollector(),
    "tech_detect": TechDetectCollector(),
    "osint": OsintCollector(),
    "screenshot": ScreenshotCollector(),
    "leaks": LeaksCollector(),
    "web_exploit": WebExploitCollector(),
    "cred_attack": CredAttackCollector(),
    "api_exploit": ApiExploitCollector(),
}
# Coletores de host (recebem IPs expandidos e rodam em lote).
HOST_COLLECTORS = {"host_discovery", "port_scan", "http_probe", "web_content",
                   "content_discovery", "web_vuln", "tech_detect", "screenshot",
                   "web_exploit", "cred_attack", "api_exploit"}

# Coletores de EXPLORACAO (gated): so' rodam com autorizacao de exploracao.
EXPLOIT_COLLECTORS = {"web_exploit", "cred_attack", "api_exploit"}

# Ordem canonica das ETAPAS do pipeline (quando varias sao selecionadas).
# Cada etapa usa o resultado da anterior (hosts vivos -> portas -> web...).
STAGE_ORDER = [
    "subdomain_enum", "osint", "host_discovery", "port_scan", "http_probe",
    "tech_detect", "web_content", "content_discovery", "web_vuln",
    "web_exploit", "api_exploit", "cred_attack", "screenshot", "wayback",
    "google_dorks", "leaks",
]

# Rotulo funcional (UI nunca ve o nome do binario).
STAGE_LABELS = {
    "subdomain_enum": "Enumeração de ativos",
    "osint": "OSINT (e-mails, domínios, IPs)",
    "host_discovery": "Descoberta de hosts ativos",
    "port_scan": "Descoberta de portas e serviços",
    "http_probe": "Reconhecimento web",
    "tech_detect": "Detecção de tecnologias",
    "web_content": "Conteúdo exposto",
    "content_discovery": "Mapeamento de conteúdo (login/API/arquivos)",
    "web_vuln": "Verificação de vulnerabilidades",
    "web_exploit": "Exploração web (XSS/SQLi)",
    "api_exploit": "Exploração de API (autorização/IDOR)",
    "cred_attack": "Ataque de credenciais (senhas fracas)",
    "screenshot": "Captura de tela",
    "wayback": "Histórico (Wayback)",
    "google_dorks": "Google Dorks",
    "leaks": "Vazamentos de credenciais",
}

# Etapas que consomem a lista de HOSTS WEB (hosts com porta web aberta no
# port_scan). Se o port_scan nao rodou neste scan, caem para hosts vivos / todos.
WEB_STAGES = {"http_probe", "tech_detect", "web_content", "content_discovery",
              "web_vuln", "web_exploit", "api_exploit", "screenshot"}

# Portas consideradas "web" para decidir quais hosts seguem para as etapas web.
WEB_PORTS = {80, 443, 8080, 8443, 8000, 3000, 9000, 8081, 8888, 5000}

# Coletores de host (port/http) sao o padrao. Os de recon (dominio) sao opt-in.
DEFAULT_COLLECTORS = ["port_scan", "http_probe"]
