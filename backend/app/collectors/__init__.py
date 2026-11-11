from app.collectors.http_probe import HttpProbeCollector
from app.collectors.port_scan import PortScanCollector

# Registro de coletores disponiveis. Adicione novos aqui.
COLLECTORS = {
    "port_scan": PortScanCollector(),
    "http_probe": HttpProbeCollector(),
}

DEFAULT_COLLECTORS = ["port_scan", "http_probe"]
