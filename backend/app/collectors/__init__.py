from app.collectors.google_dorks import GoogleDorksCollector
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

# Registro de coletores disponiveis. Ferramentas consagradas com fallback Python:
#   port_scan     -> nmap   (fallback: scanner TCP proprio)
#   subdomain_enum-> subfinder (fallback: crt.sh + wordlist)
#   web_vuln      -> nuclei (sem fallback; vazio se ausente)
COLLECTORS = {
    "port_scan": NmapCollector(),
    "http_probe": HttpProbeCollector(),
    "web_content": WebContentCollector(),
    "web_vuln": NucleiCollector(),
    "subdomain_enum": SubfinderCollector(),
    "wayback": WaybackCollector(),
    "google_dorks": GoogleDorksCollector(),
    "tech_detect": TechDetectCollector(),
    "osint": OsintCollector(),
    "screenshot": ScreenshotCollector(),
    "leaks": LeaksCollector(),
}
# Coletores de host (recebem IPs expandidos e rodam em lote).
HOST_COLLECTORS = {"port_scan", "http_probe", "web_content", "web_vuln",
                   "tech_detect", "screenshot"}

# Coletores de host (port/http) sao o padrao. Os de recon (dominio) sao opt-in.
DEFAULT_COLLECTORS = ["port_scan", "http_probe"]
