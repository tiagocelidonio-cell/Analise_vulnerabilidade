from app.collectors.google_dorks import GoogleDorksCollector
from app.collectors.http_probe import HttpProbeCollector
from app.collectors.port_scan import PortScanCollector
from app.collectors.subdomain_enum import SubdomainEnumCollector
from app.collectors.wayback import WaybackCollector

# Registro de coletores disponiveis. Adicione novos aqui.
COLLECTORS = {
    "port_scan": PortScanCollector(),
    "http_probe": HttpProbeCollector(),
    "subdomain_enum": SubdomainEnumCollector(),
    "wayback": WaybackCollector(),
    "google_dorks": GoogleDorksCollector(),
}

# Coletores de host (port/http) sao o padrao. Os de recon (dominio) sao opt-in.
DEFAULT_COLLECTORS = ["port_scan", "http_probe"]
